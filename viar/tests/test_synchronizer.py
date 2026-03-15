"""Tests for BurpVideoSynchronizer."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from viar.core.synchronizer import BurpVideoSynchronizer, SyncConfig
from viar.core.synchronizer.burp_video_sync import TimelineAnchor
from viar.models.burp import BurpHttpItem, BurpRequest, BurpResponse, BurpScanData
from viar.models.video import TemporalEvent, VideoAnalysis, VideoFrame


def make_item(offset_seconds: float, method="GET", url="http://app.example.com/test") -> BurpHttpItem:
    ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
    return BurpHttpItem(
        item_id=str(uuid.uuid4()),
        timestamp=ts,
        request=BurpRequest(method=method, url=url, path="/test", host="app.example.com"),
        response=BurpResponse(status_code=200, status_message="OK"),
    )


def make_event(offset_ms: float, event_type="click") -> TemporalEvent:
    return TemporalEvent(
        event_id=str(uuid.uuid4()),
        timestamp_ms=offset_ms,
        event_type=event_type,
        description=f"{event_type} at {offset_ms}ms",
    )


def make_frame(offset_ms: float) -> VideoFrame:
    return VideoFrame(
        frame_index=int(offset_ms / 33),
        timestamp_ms=offset_ms,
        file_path=f"/tmp/frame_{offset_ms:.0f}.jpg",
        width=1920,
        height=1080,
    )


class TestBurpVideoSynchronizer:
    def test_basic_synchronisation(self, sample_burp_scan, sample_video_analysis):
        sync = BurpVideoSynchronizer()
        result = sync.synchronise(sample_burp_scan, sample_video_analysis)
        assert result is not None
        assert len(result.correlated_events) > 0 or len(result.unmatched_burp) > 0

    def test_exact_match_within_tolerance(self):
        """An HTTP item projected to 5000ms should match a video event at 5200ms."""
        item = make_item(5.0)  # 5 seconds from Burp start
        event = make_event(5200.0)  # 5.2 seconds in video

        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=[item],
            time_range_start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            time_range_end=datetime(2024, 1, 15, 10, 0, 5, tzinfo=timezone.utc),
        )
        video = VideoAnalysis(
            video_path="/tmp/test.mp4",
            video_duration_ms=30000,
            fps=30,
            total_frames=900,
            events=[event],
            frames=[make_frame(5000), make_frame(5200)],
            recording_start_wall=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        )

        config = SyncConfig(max_sync_delta_ms=1000)
        result = BurpVideoSynchronizer(config=config).synchronise(scan, video)
        assert len(result.correlated_events) == 1
        assert result.correlated_events[0].response_status == 200

    def test_unmatched_item_when_beyond_tolerance(self):
        """Items that are too far from any video event should be unmatched."""
        item = make_item(0.0)
        event = make_event(60000.0)  # 60 seconds away

        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=[item],
            time_range_start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            time_range_end=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        video = VideoAnalysis(
            video_path="/tmp/test.mp4",
            video_duration_ms=90000,
            fps=30,
            total_frames=2700,
            events=[event],
            frames=[],  # No frames → no fallback
        )

        config = SyncConfig(max_sync_delta_ms=1000, auto_calibrate=False)
        # Manual anchor: 0s Burp → 0ms video
        config.anchors = [
            TimelineAnchor(
                burp_timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                video_offset_ms=0.0,
                confidence=1.0,
                source="test",
            )
        ]
        result = BurpVideoSynchronizer(config=config).synchronise(scan, video)
        assert len(result.unmatched_burp) == 1

    def test_attack_timeline_grouping(self):
        """Events within 10s of each other should form one timeline step."""
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        items = [make_item(i) for i in range(5)]  # 5 requests, 1s apart
        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=items,
            time_range_start=base_ts,
            time_range_end=base_ts + timedelta(seconds=4),
        )
        events = [make_event(i * 1000) for i in range(5)]
        video = VideoAnalysis(
            video_path="/tmp/test.mp4",
            video_duration_ms=10000,
            fps=30,
            total_frames=300,
            events=events,
            frames=[make_frame(i * 1000) for i in range(10)],
            recording_start_wall=base_ts,
        )

        config = SyncConfig(attack_sequence_gap_ms=10000)  # 10s gap → all in one step
        result = BurpVideoSynchronizer(config=config).synchronise(scan, video)
        assert len(result.attack_timeline) == 1

    def test_piecewise_linear_interpolation(self):
        """Interpolation between two anchors should give correct intermediate values."""
        sync = BurpVideoSynchronizer()
        a0 = TimelineAnchor(
            burp_timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            video_offset_ms=0.0,
        )
        a1 = TimelineAnchor(
            burp_timestamp=datetime(2024, 1, 15, 10, 0, 10, tzinfo=timezone.utc),
            video_offset_ms=10000.0,
        )
        mid_ts = datetime(2024, 1, 15, 10, 0, 5, tzinfo=timezone.utc)
        offset = sync._interpolate(mid_ts, [a0, a1])
        assert abs(offset - 5000.0) < 1.0  # Should be ~5000ms

    def test_empty_inputs_gracefully_handled(self):
        empty_scan = BurpScanData(source_file="empty", source_format="xml")
        empty_video = VideoAnalysis(video_path="", video_duration_ms=0, fps=0, total_frames=0)
        sync = BurpVideoSynchronizer()
        result = sync.synchronise(empty_scan, empty_video)
        assert result.correlated_events == []
        assert result.attack_timeline == []

    def test_drift_estimation(self):
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=[make_item(0), make_item(20)],
            time_range_start=base_ts,
            time_range_end=base_ts + timedelta(seconds=20),
        )
        # Video is 22 seconds = 2s drift
        video = VideoAnalysis(
            video_path="/tmp/test.mp4",
            video_duration_ms=22000,
            fps=30,
            total_frames=660,
        )
        anchors = [
            TimelineAnchor(
                burp_timestamp=base_ts,
                video_offset_ms=0,
                confidence=1.0,
                source="test",
            ),
            TimelineAnchor(
                burp_timestamp=base_ts + timedelta(seconds=20),
                video_offset_ms=20000,
                confidence=1.0,
                source="test",
            ),
        ]
        sync = BurpVideoSynchronizer()
        drift = sync._estimate_drift(anchors, scan, video)
        assert abs(drift - 2000.0) < 100  # 2000ms drift
