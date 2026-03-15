"""
Temporal (sequential) analysis of video frames using a vision LLM.

Analyses groups of frames in sequence to understand the *intent* and *flow*
of an attack, not just individual screen states.
"""
from __future__ import annotations

import base64
import logging
import uuid
from pathlib import Path
from typing import Any, Optional

from viar.models.video import TemporalEvent, VideoAnalysis, VideoFrame, VideoSegment

logger = logging.getLogger(__name__)

# How many frames to include in each vision-model call
_FRAMES_PER_BATCH = 8
# Overlap between consecutive batches (for temporal continuity)
_BATCH_OVERLAP = 2


class TemporalAnalyzer:
    """
    Analyses video frames in overlapping temporal batches using a vision model.

    Each batch is sent to the LLM with the prompt:
    "You are a senior penetration tester reviewing a screen recording. These
    frames are sequential. Describe what the attacker is doing, what input
    they are modifying, and what the server response indicates."

    The resulting events are stitched together and deduplicated.
    """

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        """
        Args:
            llm_client: An Anthropic or LangChain chat client with vision support.
            model: Model identifier to use for vision analysis.
        """
        self.llm = llm_client
        self.model = model

    def analyse(self, analysis: VideoAnalysis) -> VideoAnalysis:
        """Enrich a VideoAnalysis with temporal events and segments."""
        if not analysis.frames:
            return analysis

        all_events: list[TemporalEvent] = []
        all_segments: list[VideoSegment] = []

        batches = self._create_batches(analysis.frames)
        context: list[str] = []  # Running narrative context between batches

        for batch_idx, batch in enumerate(batches):
            logger.debug("Analysing batch %d/%d", batch_idx + 1, len(batches))
            events, segments, context = self._analyse_batch(
                batch, batch_idx, context
            )
            all_events.extend(events)
            all_segments.extend(segments)

        # Deduplicate events that appear in overlapping batches
        all_events = self._deduplicate_events(all_events)

        # Build overall narrative from accumulated context
        narrative = self._synthesise_narrative(context)

        return analysis.model_copy(
            update={
                "events": all_events,
                "segments": all_segments,
                "overall_narrative": narrative,
            }
        )

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _create_batches(
        self, frames: list[VideoFrame]
    ) -> list[list[VideoFrame]]:
        batches: list[list[VideoFrame]] = []
        step = _FRAMES_PER_BATCH - _BATCH_OVERLAP
        i = 0
        while i < len(frames):
            batches.append(frames[i : i + _FRAMES_PER_BATCH])
            i += step
        return batches

    def _analyse_batch(
        self,
        frames: list[VideoFrame],
        batch_idx: int,
        prior_context: list[str],
    ) -> tuple[list[TemporalEvent], list[VideoSegment], list[str]]:
        """Send a batch of frames to the vision model and parse the response."""
        context_prompt = ""
        if prior_context:
            # Summarise previous context (last 3 observations)
            context_prompt = (
                "Previous observations:\n"
                + "\n".join(f"- {c}" for c in prior_context[-3:])
                + "\n\n"
            )

        messages = self._build_messages(frames, context_prompt)

        try:
            response = self.llm.invoke(messages)
            text = response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            logger.warning("Vision model call failed for batch %d: %s", batch_idx, exc)
            return [], [], prior_context

        events, segments = self._parse_llm_response(text, frames)
        # Append this batch's summary to running context
        updated_context = list(prior_context) + [text[:500]]
        return events, segments, updated_context

    def _build_messages(
        self, frames: list[VideoFrame], context_prompt: str
    ) -> list[dict]:
        """Build multimodal message with frame images embedded as base64."""
        content: list[dict] = [
            {
                "type": "text",
                "text": (
                    f"{context_prompt}"
                    "You are a senior penetration tester reviewing a screen recording of a security assessment. "
                    "The following frames are sequential screenshots from the recording. "
                    "Analyse them as a temporal sequence and identify:\n"
                    "1. What the tester is doing (clicks, inputs, navigations)\n"
                    "2. What parameters or values are being modified\n"
                    "3. What server responses indicate (errors, data leaks, access grants)\n"
                    "4. Any observable attack pattern (e.g. IDOR attempt, SQLi payload, privilege escalation)\n\n"
                    "Respond in JSON with this structure:\n"
                    '{"events": [{"timestamp_ms": <float>, "event_type": <str>, "description": <str>, "payload": <dict|null>}], '
                    '"segment_label": <str>, "segment_description": <str>}'
                ),
            }
        ]

        for frame in frames:
            path = Path(frame.file_path)
            if not path.exists():
                continue
            b64 = base64.standard_b64encode(path.read_bytes()).decode()
            ext = path.suffix.lstrip(".").lower()
            media_type = f"image/{ext}" if ext in ("jpg", "jpeg", "png", "gif", "webp") else "image/jpeg"
            content.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": b64,
                    },
                }
            )

        return [{"role": "user", "content": content}]

    def _parse_llm_response(
        self, text: str, frames: list[VideoFrame]
    ) -> tuple[list[TemporalEvent], list[VideoSegment]]:
        """Extract structured events and segments from LLM response text."""
        import json
        import re

        events: list[TemporalEvent] = []
        segments: list[VideoSegment] = []

        # Extract JSON block from the response
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if not json_match:
            return events, segments

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError:
            logger.debug("Could not parse JSON from vision response")
            return events, segments

        # Build frame timestamp map for nearest-frame lookup
        frame_map = {f.timestamp_ms: f for f in frames}
        frame_timestamps = sorted(frame_map.keys())

        for ev_dict in data.get("events", []):
            ts_ms = float(ev_dict.get("timestamp_ms") or 0)
            nearest_ts = min(frame_timestamps, key=lambda t: abs(t - ts_ms), default=0)
            nearest_frame = frame_map.get(nearest_ts)

            events.append(
                TemporalEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp_ms=ts_ms,
                    event_type=ev_dict.get("event_type", "unknown"),
                    description=ev_dict.get("description", ""),
                    frame=nearest_frame,
                    payload=ev_dict.get("payload"),
                )
            )

        if data.get("segment_label") and frames:
            segments.append(
                VideoSegment(
                    segment_id=str(uuid.uuid4()),
                    start_ms=frames[0].timestamp_ms,
                    end_ms=frames[-1].timestamp_ms,
                    label=data["segment_label"],
                    description=data.get("segment_description", ""),
                    frames=frames,
                    key_frames=frames[:1],
                )
            )

        return events, segments

    def _deduplicate_events(
        self, events: list[TemporalEvent]
    ) -> list[TemporalEvent]:
        """Remove near-duplicate events from overlapping batches."""
        seen: set[str] = set()
        unique: list[TemporalEvent] = []
        for ev in sorted(events, key=lambda e: e.timestamp_ms):
            key = f"{round(ev.timestamp_ms, -2)}|{ev.event_type}|{ev.description[:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(ev)
        return unique

    def _synthesise_narrative(self, context: list[str]) -> Optional[str]:
        if not context:
            return None
        try:
            response = self.llm.invoke(
                [
                    {
                        "role": "user",
                        "content": (
                            "Based on these sequential observations from a penetration test recording, "
                            "write a concise 3-paragraph narrative explaining the attack flow from start to finish. "
                            "Use clear, professional security language.\n\n"
                            "Observations:\n"
                            + "\n".join(f"- {c[:300]}" for c in context)
                        ),
                    }
                ]
            )
            return response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            logger.warning("Failed to synthesise narrative: %s", exc)
            return None
