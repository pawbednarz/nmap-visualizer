"""
OpenCV-based frame extractor for pentest recording videos.

Extracts key-frames using scene-change detection to avoid flooding
downstream agents with redundant frames.
"""
from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import cv2
import numpy as np

from viar.models.video import VideoAnalysis, VideoFrame

logger = logging.getLogger(__name__)


@dataclass
class ExtractionConfig:
    """Tunable parameters for frame extraction."""

    # Frames per second to sample (0 = use scene-change detection only)
    sample_fps: float = 1.0
    # Minimum pixel difference between consecutive frames (scene change threshold)
    scene_change_threshold: float = 30.0
    # Maximum total frames to extract (prevents memory issues on long recordings)
    max_frames: int = 500
    # Output directory for extracted frame images
    output_dir: Optional[str] = None
    # JPEG quality for saved frames
    jpeg_quality: int = 85


class FrameExtractor:
    """
    Extracts representative frames from a video recording.

    Uses a dual strategy:
    1. Regular temporal sampling at `sample_fps`
    2. Scene-change detection to catch rapid state transitions
       (e.g., a server error page appearing briefly)
    """

    def __init__(self, config: Optional[ExtractionConfig] = None):
        self.config = config or ExtractionConfig()

    def extract(self, video_path: str | Path) -> VideoAnalysis:
        """Extract frames and return a VideoAnalysis with frame metadata."""
        video_path = Path(video_path)
        if not video_path.exists():
            raise FileNotFoundError(f"Video not found: {video_path}")

        output_dir = Path(self.config.output_dir or (video_path.parent / f"{video_path.stem}_frames"))
        output_dir.mkdir(parents=True, exist_ok=True)

        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            raise RuntimeError(f"Cannot open video: {video_path}")

        try:
            return self._extract_frames(cap, video_path, output_dir)
        finally:
            cap.release()

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _extract_frames(
        self, cap: cv2.VideoCapture, video_path: Path, output_dir: Path
    ) -> VideoAnalysis:
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration_ms = (total_frames / fps) * 1000.0

        sample_interval = max(1, int(fps / self.config.sample_fps)) if self.config.sample_fps > 0 else int(fps)

        frames: list[VideoFrame] = []
        prev_gray: Optional[np.ndarray] = None
        frame_idx = 0
        extracted_count = 0

        while extracted_count < self.config.max_frames:
            ret, frame_bgr = cap.read()
            if not ret:
                break

            timestamp_ms = (frame_idx / fps) * 1000.0
            gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)

            should_extract = (frame_idx % sample_interval == 0) or self._is_scene_change(prev_gray, gray)

            if should_extract:
                file_path = str(output_dir / f"frame_{frame_idx:06d}.jpg")
                cv2.imwrite(
                    file_path,
                    frame_bgr,
                    [cv2.IMWRITE_JPEG_QUALITY, self.config.jpeg_quality],
                )
                h, w = frame_bgr.shape[:2]
                frames.append(
                    VideoFrame(
                        frame_index=frame_idx,
                        timestamp_ms=timestamp_ms,
                        file_path=file_path,
                        width=w,
                        height=h,
                    )
                )
                extracted_count += 1

            prev_gray = gray
            frame_idx += 1

        logger.info(
            "Extracted %d frames from %s (%.1fs, %.1f fps)",
            extracted_count,
            video_path.name,
            duration_ms / 1000,
            fps,
        )

        return VideoAnalysis(
            video_path=str(video_path),
            video_duration_ms=duration_ms,
            fps=fps,
            total_frames=total_frames,
            frames=frames,
        )

    def _is_scene_change(
        self, prev: Optional[np.ndarray], curr: np.ndarray
    ) -> bool:
        if prev is None:
            return True
        diff = cv2.absdiff(prev, curr)
        mean_diff = float(np.mean(diff))
        return mean_diff > self.config.scene_change_threshold
