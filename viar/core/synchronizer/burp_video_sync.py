"""
BurpVideoSynchronizer — Core temporal correlation engine for VIAR.

This module is the heart of the VIAR system. It aligns Burp Suite HTTP traffic
with video recording events on a shared timeline, enabling:

  - Per-frame identification of which HTTP request was in-flight
  - Association of server responses with visible UI reactions
  - Detection of multi-step attack sequences across both data sources
  - Generation of a unified "attack timeline" for the reporting layer

Architecture:
  ┌──────────────┐    ┌────────────────┐
  │  BurpScanData │    │  VideoAnalysis  │
  └──────┬───────┘    └───────┬────────┘
         │                    │
         ▼                    ▼
  ┌──────────────────────────────────────┐
  │          TimelineAnchor              │
  │  (maps Burp wall-clock → video ms)   │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │      CorrelationEngine               │
  │  nearest-neighbour + window matching │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │           SyncResult                 │
  │  correlated_events + attack_timeline │
  └──────────────────────────────────────┘
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from viar.models.burp import BurpHttpItem, BurpScanData
from viar.models.video import TemporalEvent, VideoAnalysis

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class TimelineAnchor:
    """
    Calibration anchor that maps between Burp wall-clock time and video time.

    At least one anchor is required for synchronisation. Multiple anchors
    reduce drift accumulation over long recordings.

    Fields:
        burp_timestamp:  The wall-clock datetime from a Burp HTTP item.
        video_offset_ms: The corresponding position in the video (in ms).
        confidence:      0.0–1.0; higher = used for primary calibration.
        source:          How this anchor was derived ("manual", "auto-heuristic",
                         "title-match", "response-time").
    """

    burp_timestamp: datetime
    video_offset_ms: float
    confidence: float = 1.0
    source: str = "manual"


@dataclass
class CorrelatedEvent:
    """
    A single point on the unified attack timeline.

    Combines a Burp HTTP item with the closest video event(s), plus
    derived context about what was happening on-screen at that moment.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Unified timestamp (milliseconds from video start)
    video_offset_ms: float = 0.0
    # Wall-clock time from Burp (UTC)
    burp_timestamp: Optional[datetime] = None

    # Source data
    burp_item: Optional[BurpHttpItem] = None
    video_event: Optional[TemporalEvent] = None

    # Derived fields (populated by CorrelationEngine)
    request_method: str = ""
    request_url: str = ""
    response_status: Optional[int] = None
    # Delta (ms) between Burp item and closest video event
    sync_delta_ms: float = 0.0
    # Screen caption at the correlated frame
    screen_caption: Optional[str] = None
    # Whether this event was part of a detected attack sequence
    is_attack_event: bool = False
    # Qualitative label (e.g. "parameter-tamper", "auth-check", "data-exfil")
    label: Optional[str] = None


@dataclass
class AttackTimelineEntry:
    """
    High-level step in the reconstructed attack timeline.

    Groups one or more correlated events into a semantic unit that
    can be narrated in the report.
    """

    step: int
    start_offset_ms: float
    end_offset_ms: float
    label: str
    description: str
    events: list[CorrelatedEvent] = field(default_factory=list)
    # Representative Burp item for PoC extraction
    primary_burp_item: Optional[BurpHttpItem] = None
    # Representative video frame path
    primary_frame_path: Optional[str] = None


@dataclass
class SyncConfig:
    """
    Tunable parameters for the synchroniser.

    Fields:
        anchors:
            Pre-computed TimelineAnchor objects. If empty, the synchroniser
            attempts automatic calibration using heuristics.
        auto_calibrate:
            When True and no anchors are provided, attempt to derive anchors
            by correlating first/last Burp timestamps with video start/end.
        max_sync_delta_ms:
            Maximum allowable time gap (ms) between a Burp item and a video
            event for them to be considered correlated. Default 5 000 ms.
        attack_sequence_gap_ms:
            Gap between correlated events that triggers a new timeline step.
            Events closer than this are grouped into the same step. Default 10 s.
        min_correlation_confidence:
            Minimum anchor confidence to use an anchor for calibration.
        label_attack_events:
            When True, ask the LLM to label interesting correlated events.
    """

    anchors: list[TimelineAnchor] = field(default_factory=list)
    auto_calibrate: bool = True
    max_sync_delta_ms: float = 5_000.0
    attack_sequence_gap_ms: float = 10_000.0
    min_correlation_confidence: float = 0.5
    label_attack_events: bool = False


@dataclass
class SyncResult:
    """
    Complete output of a BurpVideoSynchronizer run.

    Fields:
        correlated_events:  All matched Burp-video event pairs on the timeline.
        unmatched_burp:     Burp items with no video event within tolerance.
        unmatched_video:    Video events with no Burp item within tolerance.
        attack_timeline:    Semantically grouped attack steps.
        calibration_used:   Anchors actually used for calibration.
        drift_ms:           Estimated total clock drift across the recording.
    """

    correlated_events: list[CorrelatedEvent] = field(default_factory=list)
    unmatched_burp: list[BurpHttpItem] = field(default_factory=list)
    unmatched_video: list[TemporalEvent] = field(default_factory=list)
    attack_timeline: list[AttackTimelineEntry] = field(default_factory=list)
    calibration_used: list[TimelineAnchor] = field(default_factory=list)
    drift_ms: float = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────


class BurpVideoSynchronizer:
    """
    Aligns Burp Suite traffic with a video recording on a shared timeline.

    Usage
    -----
    >>> sync = BurpVideoSynchronizer(config=SyncConfig(auto_calibrate=True))
    >>> result = sync.synchronise(burp_data, video_analysis)
    >>> for ev in result.attack_timeline:
    ...     print(ev.step, ev.label, ev.start_offset_ms)

    Synchronisation Algorithm
    -------------------------
    1. **Calibration** — Build a piecewise-linear map between Burp wall-clock
       time and video milliseconds using TimelineAnchor points.

    2. **Projection** — For each Burp HTTP item, convert its wall-clock timestamp
       to a projected video offset using the calibration map.

    3. **Nearest-Neighbour Matching** — For each projected Burp item, find the
       video TemporalEvent within `max_sync_delta_ms`. Use a sorted-list binary
       search for O(n log n) performance.

    4. **Window Matching** (fallback) — If no exact video event is found,
       associate the Burp item with the video frame at the projected offset,
       creating a synthetic TemporalEvent from the frame's caption.

    5. **Attack Sequencing** — Sort all correlated events by timeline offset and
       group them into AttackTimelineEntry steps using the `attack_sequence_gap_ms`
       threshold. Events closer together than this gap form a single step.
    """

    def __init__(self, config: Optional[SyncConfig] = None):
        self.config = config or SyncConfig()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def synchronise(
        self,
        burp_data: BurpScanData,
        video_analysis: VideoAnalysis,
    ) -> SyncResult:
        """
        Main entry point: correlate Burp traffic with video events.

        Args:
            burp_data:      Parsed and noise-filtered Burp traffic.
            video_analysis: Frame-extracted and temporally-analysed video.

        Returns:
            SyncResult with correlated events and attack timeline.
        """
        logger.info(
            "Starting synchronisation: %d Burp items, %d video events",
            len(burp_data.http_items),
            len(video_analysis.events),
        )

        # Step 1: Calibration
        anchors = self._build_calibration(burp_data, video_analysis)
        if not anchors:
            logger.warning(
                "No calibration anchors available — using zero-offset assumption"
            )
            anchors = [
                TimelineAnchor(
                    burp_timestamp=burp_data.time_range_start or datetime.now(timezone.utc),
                    video_offset_ms=0.0,
                    confidence=0.1,
                    source="fallback-zero",
                )
            ]

        # Step 2: Project Burp timestamps to video offsets
        burp_projected = self._project_burp_items(burp_data.http_items, anchors)

        # Step 3 & 4: Match projected items to video events
        correlated, unmatched_burp, unmatched_video = self._correlate(
            burp_projected, video_analysis
        )

        # Step 5: Build attack timeline
        timeline = self._build_attack_timeline(correlated)

        # Estimate drift
        drift = self._estimate_drift(anchors, burp_data, video_analysis)

        result = SyncResult(
            correlated_events=correlated,
            unmatched_burp=unmatched_burp,
            unmatched_video=unmatched_video,
            attack_timeline=timeline,
            calibration_used=anchors,
            drift_ms=drift,
        )

        logger.info(
            "Synchronisation complete: %d correlated, %d unmatched Burp, "
            "%d unmatched video, %d timeline steps",
            len(correlated),
            len(unmatched_burp),
            len(unmatched_video),
            len(timeline),
        )
        return result

    # ------------------------------------------------------------------ #
    # Step 1: Calibration
    # ------------------------------------------------------------------ #

    def _build_calibration(
        self,
        burp_data: BurpScanData,
        video_analysis: VideoAnalysis,
    ) -> list[TimelineAnchor]:
        """
        Build the set of anchors used for time-mapping.

        Priority order:
          1. Manually-supplied anchors (config.anchors)
          2. Auto-calibration heuristics (if config.auto_calibrate)
        """
        anchors: list[TimelineAnchor] = []

        # Use manually supplied anchors first
        for anchor in self.config.anchors:
            if anchor.confidence >= self.config.min_correlation_confidence:
                anchors.append(anchor)

        if not anchors and self.config.auto_calibrate:
            anchors = self._auto_calibrate(burp_data, video_analysis)

        return sorted(anchors, key=lambda a: a.burp_timestamp)

    def _auto_calibrate(
        self,
        burp_data: BurpScanData,
        video_analysis: VideoAnalysis,
    ) -> list[TimelineAnchor]:
        """
        Derive calibration anchors automatically.

        Heuristics:
        A) First Burp request  → video offset 0 ms  (recording started with scan)
        B) Last Burp request   → video end ms        (recording covered full scan)
        C) If the video has a recording_start_wall, use it for absolute alignment.

        These produce a linear map that's accurate enough for a ±2s drift.
        """
        anchors: list[TimelineAnchor] = []

        if not burp_data.http_items:
            return anchors

        sorted_items = sorted(burp_data.http_items, key=lambda i: i.timestamp)
        first_item = sorted_items[0]
        last_item = sorted_items[-1]

        # Heuristic C: wall-clock anchor via recording start
        if video_analysis.recording_start_wall:
            rec_start = video_analysis.recording_start_wall.replace(tzinfo=timezone.utc)
            first_ts = first_item.timestamp.replace(tzinfo=timezone.utc)
            offset_ms = (first_ts - rec_start).total_seconds() * 1000.0
            if 0 <= offset_ms <= video_analysis.video_duration_ms:
                anchors.append(
                    TimelineAnchor(
                        burp_timestamp=first_item.timestamp,
                        video_offset_ms=offset_ms,
                        confidence=0.9,
                        source="recording-start-wall-clock",
                    )
                )
                logger.debug("Auto-anchor (wall-clock): %.1f ms", offset_ms)
                return anchors

        # Heuristic A: assume first Burp item aligns to video start
        anchors.append(
            TimelineAnchor(
                burp_timestamp=first_item.timestamp,
                video_offset_ms=0.0,
                confidence=0.6,
                source="auto-first-item",
            )
        )

        # Heuristic B: assume last Burp item aligns to video end
        if first_item.timestamp != last_item.timestamp:
            anchors.append(
                TimelineAnchor(
                    burp_timestamp=last_item.timestamp,
                    video_offset_ms=video_analysis.video_duration_ms,
                    confidence=0.6,
                    source="auto-last-item",
                )
            )

        logger.debug(
            "Auto-calibrated with %d heuristic anchors", len(anchors)
        )
        return anchors

    # ------------------------------------------------------------------ #
    # Step 2: Projection
    # ------------------------------------------------------------------ #

    def _project_burp_items(
        self,
        items: list[BurpHttpItem],
        anchors: list[TimelineAnchor],
    ) -> list[tuple[BurpHttpItem, float]]:
        """
        Convert each Burp item's wall-clock timestamp to a video offset (ms).

        Uses piecewise-linear interpolation between anchors.
        """
        if not anchors:
            return [(item, 0.0) for item in items]

        projected: list[tuple[BurpHttpItem, float]] = []
        for item in items:
            offset_ms = self._interpolate(item.timestamp, anchors)
            projected.append((item, offset_ms))

        return projected

    def _interpolate(
        self, ts: datetime, anchors: list[TimelineAnchor]
    ) -> float:
        """
        Piecewise-linear interpolation between anchor points.

        For a timestamp before the first anchor or after the last anchor,
        the nearest segment is extrapolated linearly.
        """
        if len(anchors) == 1:
            # Single anchor: constant offset
            delta = (
                ts.replace(tzinfo=timezone.utc)
                - anchors[0].burp_timestamp.replace(tzinfo=timezone.utc)
            ).total_seconds() * 1000.0
            return anchors[0].video_offset_ms + delta

        # Find surrounding anchors
        ts_utc = ts.replace(tzinfo=timezone.utc)
        for i in range(len(anchors) - 1):
            a0, a1 = anchors[i], anchors[i + 1]
            t0 = a0.burp_timestamp.replace(tzinfo=timezone.utc)
            t1 = a1.burp_timestamp.replace(tzinfo=timezone.utc)
            if t0 <= ts_utc <= t1:
                # Interpolate within this segment
                seg_duration_s = (t1 - t0).total_seconds()
                if seg_duration_s == 0:
                    return a0.video_offset_ms
                ratio = (ts_utc - t0).total_seconds() / seg_duration_s
                return a0.video_offset_ms + ratio * (a1.video_offset_ms - a0.video_offset_ms)

        # Extrapolate beyond anchors using the nearest segment
        if ts_utc < anchors[0].burp_timestamp.replace(tzinfo=timezone.utc):
            a0, a1 = anchors[0], anchors[1]
        else:
            a0, a1 = anchors[-2], anchors[-1]

        t0 = a0.burp_timestamp.replace(tzinfo=timezone.utc)
        t1 = a1.burp_timestamp.replace(tzinfo=timezone.utc)
        seg_duration_s = (t1 - t0).total_seconds()
        if seg_duration_s == 0:
            return a0.video_offset_ms
        ratio = (ts_utc - t0).total_seconds() / seg_duration_s
        return a0.video_offset_ms + ratio * (a1.video_offset_ms - a0.video_offset_ms)

    # ------------------------------------------------------------------ #
    # Steps 3 & 4: Matching
    # ------------------------------------------------------------------ #

    def _correlate(
        self,
        burp_projected: list[tuple[BurpHttpItem, float]],
        video_analysis: VideoAnalysis,
    ) -> tuple[list[CorrelatedEvent], list[BurpHttpItem], list[TemporalEvent]]:
        """
        Nearest-neighbour match between projected Burp items and video events.

        For each Burp item:
        1. Binary-search the sorted video event list for the closest event.
        2. If within tolerance: create CorrelatedEvent (Step 3).
        3. Else: create CorrelatedEvent from nearest video frame (Step 4).
        """
        correlated: list[CorrelatedEvent] = []
        unmatched_burp: list[BurpHttpItem] = []

        # Sort video events by timestamp for binary search
        video_events = sorted(video_analysis.events, key=lambda e: e.timestamp_ms)
        video_offsets = [e.timestamp_ms for e in video_events]

        # Build a frame index for fallback window matching
        frame_by_offset = {f.timestamp_ms: f for f in video_analysis.frames}
        frame_offsets = sorted(frame_by_offset.keys())

        matched_video_ids: set[str] = set()

        for item, projected_ms in burp_projected:
            nearest_event, delta_ms = self._nearest_video_event(
                projected_ms, video_events, video_offsets
            )

            if nearest_event and delta_ms <= self.config.max_sync_delta_ms:
                # Step 3: exact event match
                screen_caption = self._get_frame_caption(
                    nearest_event.frame, frame_by_offset, frame_offsets, projected_ms
                )
                correlated.append(
                    self._build_correlated_event(
                        item=item,
                        projected_ms=projected_ms,
                        video_event=nearest_event,
                        delta_ms=delta_ms,
                        screen_caption=screen_caption,
                    )
                )
                matched_video_ids.add(nearest_event.event_id)
            else:
                # Step 4: fallback to nearest frame
                nearest_frame = self._nearest_frame(
                    projected_ms, frame_by_offset, frame_offsets
                )
                if nearest_frame:
                    synthetic_event = TemporalEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp_ms=nearest_frame.timestamp_ms,
                        event_type="frame-fallback",
                        description=nearest_frame.caption or f"Frame at {nearest_frame.timestamp_ms:.0f}ms",
                        frame=nearest_frame,
                        burp_item_ids=[item.item_id],
                    )
                    correlated.append(
                        self._build_correlated_event(
                            item=item,
                            projected_ms=projected_ms,
                            video_event=synthetic_event,
                            delta_ms=abs(nearest_frame.timestamp_ms - projected_ms),
                            screen_caption=nearest_frame.caption,
                        )
                    )
                else:
                    unmatched_burp.append(item)

        # Find video events that had no matching Burp item
        unmatched_video = [
            ev for ev in video_events if ev.event_id not in matched_video_ids
        ]

        return correlated, unmatched_burp, unmatched_video

    def _nearest_video_event(
        self,
        target_ms: float,
        events: list[TemporalEvent],
        offsets: list[float],
    ) -> tuple[Optional[TemporalEvent], float]:
        """Binary search for the nearest video event to target_ms."""
        if not events:
            return None, float("inf")

        import bisect
        idx = bisect.bisect_left(offsets, target_ms)

        candidates: list[tuple[float, int]] = []
        for i in (idx - 1, idx):
            if 0 <= i < len(events):
                candidates.append((abs(offsets[i] - target_ms), i))

        if not candidates:
            return None, float("inf")

        delta, best_idx = min(candidates)
        return events[best_idx], delta

    def _nearest_frame(
        self,
        target_ms: float,
        frame_by_offset: dict[float, object],
        frame_offsets: list[float],
    ) -> Optional[object]:
        """Return the video frame whose offset is closest to target_ms."""
        if not frame_offsets:
            return None
        import bisect
        idx = bisect.bisect_left(frame_offsets, target_ms)
        best_offset = min(
            (o for o in frame_offsets[max(0, idx - 1) : idx + 1]),
            key=lambda o: abs(o - target_ms),
            default=None,
        )
        return frame_by_offset.get(best_offset) if best_offset is not None else None

    def _get_frame_caption(
        self,
        frame: Optional[object],
        frame_by_offset: dict,
        frame_offsets: list[float],
        projected_ms: float,
    ) -> Optional[str]:
        if frame and hasattr(frame, "caption"):
            return frame.caption  # type: ignore[union-attr]
        nearest = self._nearest_frame(projected_ms, frame_by_offset, frame_offsets)
        return nearest.caption if nearest and hasattr(nearest, "caption") else None  # type: ignore[union-attr]

    # ------------------------------------------------------------------ #
    # Step 5: Attack timeline construction
    # ------------------------------------------------------------------ #

    def _build_attack_timeline(
        self, correlated: list[CorrelatedEvent]
    ) -> list[AttackTimelineEntry]:
        """
        Group correlated events into sequential attack steps.

        Events within `attack_sequence_gap_ms` of each other form one step.
        Each step is assigned a label derived from the dominant event type.
        """
        if not correlated:
            return []

        sorted_events = sorted(correlated, key=lambda e: e.video_offset_ms)
        steps: list[AttackTimelineEntry] = []
        current_group: list[CorrelatedEvent] = [sorted_events[0]]

        for ev in sorted_events[1:]:
            gap = ev.video_offset_ms - current_group[-1].video_offset_ms
            if gap <= self.config.attack_sequence_gap_ms:
                current_group.append(ev)
            else:
                steps.append(self._group_to_step(len(steps) + 1, current_group))
                current_group = [ev]

        if current_group:
            steps.append(self._group_to_step(len(steps) + 1, current_group))

        return steps

    def _group_to_step(
        self, step_num: int, events: list[CorrelatedEvent]
    ) -> AttackTimelineEntry:
        """Convert a group of correlated events into an AttackTimelineEntry."""
        start_ms = events[0].video_offset_ms
        end_ms = events[-1].video_offset_ms

        # Choose most representative Burp item (prefer non-200 responses)
        primary = next(
            (e for e in events if e.response_status and e.response_status != 200),
            events[0],
        )

        label = self._derive_label(events)
        description = self._describe_step(events)

        primary_frame_path: Optional[str] = None
        if primary.video_event and primary.video_event.frame:
            primary_frame_path = primary.video_event.frame.file_path

        return AttackTimelineEntry(
            step=step_num,
            start_offset_ms=start_ms,
            end_offset_ms=end_ms,
            label=label,
            description=description,
            events=events,
            primary_burp_item=primary.burp_item,
            primary_frame_path=primary_frame_path,
        )

    def _derive_label(self, events: list[CorrelatedEvent]) -> str:
        """Heuristically label a group of events based on HTTP patterns."""
        methods = {e.request_method for e in events}
        urls = [e.request_url for e in events]
        statuses = [e.response_status for e in events if e.response_status]

        # Auth-related patterns
        if any("login" in u or "auth" in u or "token" in u for u in urls):
            return "authentication-flow"

        # Error responses suggesting an exploit attempt
        if any(s in (500, 502, 503) for s in statuses):
            return "exploit-attempt-error-response"

        # Redirect chain (common after auth bypass)
        if any(s in (301, 302, 303, 307, 308) for s in statuses):
            return "redirect-chain"

        # Write operations
        if methods & {"POST", "PUT", "PATCH", "DELETE"}:
            return "data-modification"

        # Parameter enumeration
        if len(set(urls)) > 3:
            return "endpoint-enumeration"

        return "reconnaissance"

    def _describe_step(self, events: list[CorrelatedEvent]) -> str:
        """Build a concise description of what happened during this step."""
        unique_urls = list(dict.fromkeys(e.request_url for e in events))[:3]
        statuses = [e.response_status for e in events if e.response_status]
        status_summary = ", ".join(str(s) for s in sorted(set(statuses)))

        desc_parts = [
            f"{len(events)} request(s) to {', '.join(unique_urls)}",
        ]
        if status_summary:
            desc_parts.append(f"server responded with HTTP {status_summary}")
        if any(e.screen_caption for e in events):
            caption = next(e.screen_caption for e in events if e.screen_caption)
            desc_parts.append(f'screen showed: "{caption[:100]}"')

        return "; ".join(desc_parts) + "."

    # ------------------------------------------------------------------ #
    # Helper: drift estimation
    # ------------------------------------------------------------------ #

    def _estimate_drift(
        self,
        anchors: list[TimelineAnchor],
        burp_data: BurpScanData,
        video_analysis: VideoAnalysis,
    ) -> float:
        """
        Estimate total clock drift across the recording in milliseconds.

        Drift is computed as the difference between the expected video end
        offset (derived from Burp duration) and the actual video duration.
        """
        if len(anchors) < 2 or not burp_data.duration_seconds:
            return 0.0

        burp_duration_ms = burp_data.duration_seconds * 1000.0
        video_duration_ms = video_analysis.video_duration_ms
        return abs(video_duration_ms - burp_duration_ms)

    # ------------------------------------------------------------------ #
    # Build a single CorrelatedEvent
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_correlated_event(
        item: BurpHttpItem,
        projected_ms: float,
        video_event: TemporalEvent,
        delta_ms: float,
        screen_caption: Optional[str],
    ) -> CorrelatedEvent:
        return CorrelatedEvent(
            video_offset_ms=projected_ms,
            burp_timestamp=item.timestamp,
            burp_item=item,
            video_event=video_event,
            request_method=item.request.method,
            request_url=item.request.url,
            response_status=item.response.status_code if item.response else None,
            sync_delta_ms=delta_ms,
            screen_caption=screen_caption,
        )
