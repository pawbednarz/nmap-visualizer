"""Security finding and attack-chain models."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnCategory(str, Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    IDOR = "Insecure Direct Object Reference"
    BAC = "Broken Access Control"
    AUTH_BYPASS = "Authentication Bypass"
    SSRF = "Server-Side Request Forgery"
    SSTI = "Server-Side Template Injection"
    XXE = "XML External Entity"
    OPEN_REDIRECT = "Open Redirect"
    CSRF = "Cross-Site Request Forgery"
    SENSITIVE_EXPOSURE = "Sensitive Data Exposure"
    MISCONFIG = "Security Misconfiguration"
    DESERIALIZATION = "Insecure Deserialization"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    OTHER = "Other"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class CvssVector(BaseModel):
    """CVSS v4.0 vector components."""

    # Base metrics
    attack_vector: str  # N/A/L/P
    attack_complexity: str  # L/H
    attack_requirements: str  # N/P  (v4.0)
    privileges_required: str  # N/L/H
    user_interaction: str  # N/P/A  (v4.0)
    # Impact metrics (Vulnerable System)
    vuln_conf_impact: str  # H/L/N
    vuln_integ_impact: str  # H/L/N
    vuln_avail_impact: str  # H/L/N
    # Impact metrics (Subsequent System)
    sub_conf_impact: str  # H/L/N
    sub_integ_impact: str  # H/L/N
    sub_avail_impact: str  # H/L/N

    base_score: float = 0.0
    vector_string: str = ""
    computed_by_agent: bool = True


class SecurityFinding(BaseModel):
    """A single security vulnerability finding."""

    finding_id: str
    title: str
    category: VulnCategory
    severity: Severity
    cvss: Optional[CvssVector] = None

    # Source references
    burp_issue_ids: list[str] = Field(default_factory=list)
    video_event_ids: list[str] = Field(default_factory=list)
    video_segment_ids: list[str] = Field(default_factory=list)

    # Technical details
    affected_url: str
    affected_parameter: Optional[str] = None
    http_method: Optional[str] = None
    evidence_request: Optional[str] = None
    evidence_response: Optional[str] = None
    proof_of_concept: Optional[str] = None

    # Agent-generated content
    technical_description: str = ""
    business_impact: str = ""
    remediation: str = ""
    remediation_code_snippets: list[dict[str, str]] = Field(default_factory=list)

    # Standards mapping
    owasp_top10: list[str] = Field(default_factory=list)
    cwe_ids: list[int] = Field(default_factory=list)
    asvs_controls: list[str] = Field(default_factory=list)

    # QA flags
    qa_verified: bool = False
    qa_notes: Optional[str] = None
    hallucination_risk: float = 0.0  # 0.0–1.0


class AttackStep(BaseModel):
    """A single step in an attack chain."""

    step_number: int
    finding_id: str
    action: str
    precondition: Optional[str] = None
    result: str
    video_timestamp_ms: Optional[float] = None
    burp_item_id: Optional[str] = None
    payload: Optional[Any] = None


class AttackChain(BaseModel):
    """A correlated sequence of findings forming a logical attack path."""

    chain_id: str
    title: str
    severity: Severity
    summary: str
    steps: list[AttackStep] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)  # finding_ids
    combined_cvss_score: Optional[float] = None
    narrative: str = ""
