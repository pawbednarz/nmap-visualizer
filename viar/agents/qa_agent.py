"""
QA Agent — critically reviews report findings for hallucinations and quality.

Responsibilities:
- Verify that each finding is supported by concrete evidence from Burp/video
- Check that remediation advice aligns with OWASP ASVS and Top 10
- Flag potentially hallucinated findings (unsupported by evidence)
- Assign hallucination_risk score (0.0 = certain, 1.0 = likely hallucinated)
- Ensure CVSS scores are plausible given the evidence
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from viar.models.finding import SecurityFinding, Severity

logger = logging.getLogger(__name__)

# ASVS v4.0 remediation guidelines per category (keyword → ASVS reference)
_ASVS_GUIDELINES: dict[str, list[str]] = {
    "sql": [
        "Use parameterised queries or prepared statements (ASVS V5.3.4)",
        "Apply allowlist input validation (ASVS V5.1.3)",
        "Use ORM frameworks where possible",
    ],
    "xss": [
        "Encode all output contextually (ASVS V5.3.3)",
        "Implement Content Security Policy headers (ASVS V14.4.3)",
        "Use a trusted auto-escaping template engine",
    ],
    "idor": [
        "Enforce server-side authorisation on every resource access (ASVS V4.2.1)",
        "Use indirect, non-sequential resource identifiers",
        "Log and alert on authorisation failures (ASVS V7.3.1)",
    ],
    "access control": [
        "Implement role-based access control (RBAC) server-side (ASVS V4.1.1)",
        "Deny by default — whitelist permitted actions",
    ],
    "auth": [
        "Implement multi-factor authentication (ASVS V2.1.1)",
        "Enforce account lockout after failed attempts (ASVS V2.2.1)",
    ],
    "ssrf": [
        "Validate and restrict outbound network calls (ASVS V10.3.2)",
        "Use an allowlist of permitted internal URLs",
    ],
    "command injection": [
        "Never pass user input to OS commands (ASVS V5.3.8)",
        "Use language built-in APIs instead of shell commands",
    ],
}


class QAAgent:
    """
    Quality Assurance agent for VIAR-generated reports.

    Performs:
    1. Evidence validation — each finding must have a non-empty request/response or PoC.
    2. Hallucination scoring — penalises findings with no HTTP evidence.
    3. Remediation enrichment — appends ASVS-aligned guidance.
    4. CVSS plausibility check — flags implausible scores via LLM.
    """

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def review(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Review all findings and return QA-annotated versions."""
        reviewed: list[SecurityFinding] = []
        for finding in findings:
            try:
                reviewed.append(self._review_finding(finding))
            except Exception as exc:
                logger.warning("QA review failed for %s: %s", finding.finding_id, exc)
                reviewed.append(finding)
        return reviewed

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _review_finding(self, finding: SecurityFinding) -> SecurityFinding:
        hallucination_risk = self._score_hallucination_risk(finding)
        asvs_notes = self._build_asvs_notes(finding)
        qa_notes_parts: list[str] = []

        if hallucination_risk > 0.7:
            qa_notes_parts.append(
                f"HIGH hallucination risk ({hallucination_risk:.2f}): "
                "No HTTP evidence found. Manual verification required."
            )

        # CVSS plausibility check
        if finding.cvss:
            cvss_issue = self._check_cvss_plausibility(finding)
            if cvss_issue:
                qa_notes_parts.append(f"CVSS concern: {cvss_issue}")

        # Remediation completeness check
        if not finding.remediation or len(finding.remediation) < 50:
            qa_notes_parts.append("Remediation guidance is sparse — enriching from ASVS.")

        # Build enriched remediation
        enriched_remediation = finding.remediation or ""
        if asvs_notes:
            enriched_remediation = enriched_remediation.rstrip() + "\n\n" + "\n".join(
                f"- {note}" for note in asvs_notes
            )

        # LLM deep QA for high/critical findings
        if finding.severity in (Severity.CRITICAL, Severity.HIGH) and hallucination_risk < 0.5:
            llm_note = self._llm_qa_review(finding)
            if llm_note:
                qa_notes_parts.append(f"LLM QA: {llm_note}")

        return finding.model_copy(
            update={
                "qa_verified": hallucination_risk < 0.6,
                "hallucination_risk": hallucination_risk,
                "qa_notes": "; ".join(qa_notes_parts) if qa_notes_parts else "Passed QA review.",
                "remediation": enriched_remediation,
            }
        )

    def _score_hallucination_risk(self, finding: SecurityFinding) -> float:
        """
        Score from 0.0 (definitely real) to 1.0 (likely hallucinated).

        Factors:
        - Has HTTP request evidence: -0.4
        - Has HTTP response evidence: -0.2
        - Has PoC: -0.2
        - Has Burp issue ID: -0.1
        - Has video event ID: -0.1
        """
        risk = 1.0
        if finding.evidence_request:
            risk -= 0.4
        if finding.evidence_response:
            risk -= 0.2
        if finding.proof_of_concept:
            risk -= 0.2
        if finding.burp_issue_ids:
            risk -= 0.1
        if finding.video_event_ids:
            risk -= 0.1
        return max(0.0, risk)

    def _build_asvs_notes(self, finding: SecurityFinding) -> list[str]:
        """Return relevant ASVS-aligned remediation notes for this finding."""
        notes: list[str] = []
        title_lower = finding.title.lower()
        category_lower = finding.category.value.lower()

        for keyword, guidelines in _ASVS_GUIDELINES.items():
            if keyword in title_lower or keyword in category_lower:
                notes.extend(guidelines)
                break  # One matching set per finding

        # Always add existing ASVS controls if present
        notes.extend(finding.asvs_controls)
        return list(dict.fromkeys(notes))  # Deduplicate preserving order

    def _check_cvss_plausibility(self, finding: SecurityFinding) -> str | None:
        """Flag obviously implausible CVSS scores."""
        cvss = finding.cvss
        if not cvss:
            return None

        # Critical severity should have CVSS >= 9.0
        if finding.severity == Severity.CRITICAL and cvss.base_score < 9.0:
            return f"CRITICAL finding has CVSS {cvss.base_score:.1f} (expected ≥ 9.0)"

        # Informational should not have CVSS > 3.9
        if finding.severity == Severity.INFORMATIONAL and cvss.base_score > 3.9:
            return f"INFORMATIONAL finding has CVSS {cvss.base_score:.1f} (expected ≤ 3.9)"

        return None

    def _llm_qa_review(self, finding: SecurityFinding) -> str | None:
        """Ask the LLM to critically evaluate a high/critical finding."""
        evidence_summary = (
            f"Request snippet: {(finding.evidence_request or '')[:300]}\n"
            f"Response snippet: {(finding.evidence_response or '')[:300]}\n"
            f"PoC: {(finding.proof_of_concept or '')[:300]}"
        )

        prompt = (
            "You are a senior security QA reviewer. Critically evaluate this pentest finding "
            "and flag any issues with accuracy, missing evidence, or over/under-stated severity.\n\n"
            f"Finding: {finding.title}\n"
            f"Severity: {finding.severity.value}\n"
            f"Description: {finding.technical_description[:400]}\n"
            f"Evidence:\n{evidence_summary}\n\n"
            "Identify any hallucinations, inaccuracies, or missing information. "
            "Respond with a single sentence summary of concerns (or 'No issues found.')."
        )

        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            text = response.content if hasattr(response, "content") else str(response)
            if "no issues" in text.lower():
                return None
            return text.strip()[:300]
        except Exception as exc:
            logger.debug("LLM QA call failed: %s", exc)
            return None
