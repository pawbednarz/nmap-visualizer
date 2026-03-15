"""Report models for VIAR output."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from .finding import AttackChain, SecurityFinding, Severity


class ReportFormat(str, Enum):
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"
    JIRA = "jira"
    DEFECTDOJO = "defectdojo"


class ReportSection(str, Enum):
    COVER = "cover"
    EXECUTIVE_SUMMARY = "executive_summary"
    SCOPE = "scope"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    ATTACK_CHAINS = "attack_chains"
    REMEDIATION_ROADMAP = "remediation_roadmap"
    APPENDIX = "appendix"


class ExecutiveSummary(BaseModel):
    """Executive summary with non-technical narrative."""

    headline: str
    narrative: str  # 3-5 paragraph storytelling format
    risk_overview: str
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    top_risks: list[str] = Field(default_factory=list)
    recommended_priorities: list[str] = Field(default_factory=list)


class RemediationSnippet(BaseModel):
    """Code fix snippet for a specific finding."""

    finding_id: str
    language: str
    framework: Optional[str] = None
    description: str
    vulnerable_code: Optional[str] = None
    fixed_code: str
    diff: Optional[str] = None  # unified diff format


class TechnicalFinding(BaseModel):
    """Full technical write-up for a finding (report section)."""

    finding: SecurityFinding
    poc_steps: list[str] = Field(default_factory=list)
    request_diff: Optional[str] = None   # before/after request diff
    response_diff: Optional[str] = None  # before/after response diff
    screenshots: list[str] = Field(default_factory=list)  # paths to key-frames
    remediation_snippets: list[RemediationSnippet] = Field(default_factory=list)


class PentestReport(BaseModel):
    """Complete pentest report produced by VIAR."""

    report_id: str
    title: str
    client_name: str
    engagement_type: str  # e.g. "Web Application Pentest"
    test_period_start: datetime
    test_period_end: datetime
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = "VIAR v1.0"

    # Source data references
    burp_files: list[str] = Field(default_factory=list)
    video_files: list[str] = Field(default_factory=list)

    executive_summary: Optional[ExecutiveSummary] = None
    scope: list[str] = Field(default_factory=list)
    methodology: Optional[str] = None
    findings: list[TechnicalFinding] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    remediation_roadmap: list[dict] = Field(default_factory=list)

    # Metadata
    overall_risk_rating: Optional[Severity] = None
    sections_included: list[ReportSection] = Field(default_factory=list)
    export_formats: list[ReportFormat] = Field(default_factory=list)
