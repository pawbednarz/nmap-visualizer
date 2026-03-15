"""Pydantic models for Burp Suite data (XML/JSON exports)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class BurpRequest(BaseModel):
    """Parsed HTTP request from Burp traffic."""

    method: str
    url: str
    path: str
    host: str
    port: int = 80
    protocol: str = "http"
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    raw: Optional[str] = None

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        return v.upper()


class BurpResponse(BaseModel):
    """Parsed HTTP response from Burp traffic."""

    status_code: int
    status_message: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    raw: Optional[str] = None
    length: int = 0


class BurpHttpItem(BaseModel):
    """Single HTTP request/response pair from Burp history."""

    item_id: str
    timestamp: datetime
    request: BurpRequest
    response: Optional[BurpResponse] = None
    # Latency in milliseconds
    latency_ms: Optional[float] = None
    # Burp-assigned mime type
    mime_type: Optional[str] = None
    # Whether item was flagged by Burp
    flagged: bool = False
    # Raw base64 request/response (kept for re-parsing)
    _raw_request_b64: Optional[str] = None
    _raw_response_b64: Optional[str] = None


class BurpScanIssue(BaseModel):
    """Vulnerability finding from Burp Scanner."""

    issue_id: str
    issue_type: int  # Burp internal type ID
    issue_name: str
    severity: str  # High / Medium / Low / Information
    confidence: str  # Certain / Firm / Tentative
    url: str
    host: str
    path: str
    detail: Optional[str] = None
    background: Optional[str] = None
    remediation: Optional[str] = None
    remediation_background: Optional[str] = None
    # HTTP traffic items associated with this finding
    http_items: list[BurpHttpItem] = Field(default_factory=list)
    # CWE identifiers if available
    cwes: list[int] = Field(default_factory=list)


class BurpScanData(BaseModel):
    """Complete parsed Burp Suite export."""

    source_file: str
    source_format: str  # "xml" | "json"
    parsed_at: datetime = Field(default_factory=datetime.utcnow)

    # All HTTP traffic items
    http_items: list[BurpHttpItem] = Field(default_factory=list)
    # Scanner findings (from active/passive scan)
    issues: list[BurpScanIssue] = Field(default_factory=list)

    # Derived aggregations computed during parsing
    unique_hosts: list[str] = Field(default_factory=list)
    unique_endpoints: list[str] = Field(default_factory=list)
    tech_fingerprints: list[str] = Field(default_factory=list)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.time_range_start and self.time_range_end:
            return (self.time_range_end - self.time_range_start).total_seconds()
        return None
