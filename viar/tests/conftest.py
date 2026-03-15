"""Shared pytest fixtures for VIAR tests."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from viar.models.burp import BurpHttpItem, BurpRequest, BurpResponse, BurpScanData, BurpScanIssue
from viar.models.finding import SecurityFinding, Severity, VulnCategory
from viar.models.video import TemporalEvent, VideoAnalysis, VideoFrame


FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ─────────────────────────────────────────────────────────────────────────────
# Burp fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_burp_request() -> BurpRequest:
    return BurpRequest(
        method="GET",
        url="http://app.example.com/api/users/1",
        path="/api/users/1",
        host="app.example.com",
        port=80,
        headers={"Host": "app.example.com", "User-Agent": "Mozilla/5.0"},
    )


@pytest.fixture()
def sample_burp_response() -> BurpResponse:
    return BurpResponse(
        status_code=200,
        status_message="OK",
        headers={"Content-Type": "application/json", "Server": "nginx/1.18.0"},
        body='{"id": 1, "email": "admin@example.com", "role": "admin"}',
        length=55,
    )


@pytest.fixture()
def sample_http_item(sample_burp_request, sample_burp_response) -> BurpHttpItem:
    return BurpHttpItem(
        item_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        request=sample_burp_request,
        response=sample_burp_response,
        mime_type="application/json",
    )


@pytest.fixture()
def sample_sqli_item() -> BurpHttpItem:
    return BurpHttpItem(
        item_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc),
        request=BurpRequest(
            method="POST",
            url="http://app.example.com/login",
            path="/login",
            host="app.example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin' OR '1'='1&password=anything",
        ),
        response=BurpResponse(
            status_code=200,
            status_message="OK",
            body='{"token": "eyJhbGciOiJIUzI1NiJ9..."}',
        ),
    )


@pytest.fixture()
def sample_burp_scan(sample_http_item, sample_sqli_item) -> BurpScanData:
    issue = BurpScanIssue(
        issue_id=str(uuid.uuid4()),
        issue_type=1049088,
        issue_name="SQL injection",
        severity="High",
        confidence="Certain",
        url="http://app.example.com/login",
        host="app.example.com",
        path="/login",
        detail="The username parameter is vulnerable to SQL injection.",
        http_items=[sample_sqli_item],
    )
    return BurpScanData(
        source_file="test_scan.xml",
        source_format="xml",
        http_items=[sample_http_item, sample_sqli_item],
        issues=[issue],
        unique_hosts=["app.example.com"],
        unique_endpoints=["GET http://app.example.com/api/users/1", "POST http://app.example.com/login"],
        tech_fingerprints=["nginx/1.18.0"],
        time_range_start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        time_range_end=datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Video fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_video_frame() -> VideoFrame:
    return VideoFrame(
        frame_index=100,
        timestamp_ms=4000.0,
        file_path="/tmp/frames/frame_000100.jpg",
        width=1920,
        height=1080,
        caption="Login form with admin username visible",
    )


@pytest.fixture()
def sample_video_event(sample_video_frame) -> TemporalEvent:
    return TemporalEvent(
        event_id=str(uuid.uuid4()),
        timestamp_ms=4500.0,
        event_type="input",
        description="User typed SQL payload in username field",
        frame=sample_video_frame,
        payload={"field": "username", "value": "admin' OR '1'='1"},
    )


@pytest.fixture()
def sample_video_analysis(sample_video_frame, sample_video_event) -> VideoAnalysis:
    return VideoAnalysis(
        video_path="/tmp/test_recording.mp4",
        video_duration_ms=30000.0,
        fps=30.0,
        total_frames=900,
        frames=[sample_video_frame],
        events=[sample_video_event],
        overall_narrative="The tester demonstrated SQL injection via the login form.",
        recording_start_wall=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Finding fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_finding() -> SecurityFinding:
    return SecurityFinding(
        finding_id=str(uuid.uuid4()),
        title="SQL Injection in login endpoint",
        category=VulnCategory.SQLI,
        severity=Severity.HIGH,
        affected_url="http://app.example.com/login",
        http_method="POST",
        affected_parameter="username",
        evidence_request="POST /login HTTP/1.1\r\nHost: app.example.com\r\n\r\nusername=admin' OR '1'='1",
        evidence_response="HTTP/1.1 200 OK\r\n\r\n{\"token\": \"...\"}",
        technical_description="The username parameter is vulnerable to SQL injection.",
        business_impact="Attacker can bypass authentication and access all user accounts.",
        remediation="Use parameterised queries.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Mock LLM
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_llm():
    """A mock LLM client that returns predictable responses."""
    mock = MagicMock()
    response = MagicMock()
    response.content = (
        '{"findings": [{"title": "Test Finding", "category": "SQL Injection", '
        '"severity": "high", "technical_description": "Test description", '
        '"affected_url": "http://example.com/login", "proof_of_concept": "Test PoC", '
        '"owasp_top10": ["A03:2021"], "cwe_ids": [89]}]}'
    )
    mock.invoke.return_value = response
    return mock
