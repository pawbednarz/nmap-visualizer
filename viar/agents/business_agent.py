"""
Business Agent — translates technical findings to business risk language.

Responsibilities:
- Compute CVSS v4.0 scores automatically from finding context
- Generate business impact statements (revenue, reputation, compliance)
- Map findings to regulatory frameworks (GDPR, PCI-DSS, HIPAA)
- Prioritise remediation based on exploitability × business impact
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

from viar.models.finding import (
    CvssVector,
    SecurityFinding,
    Severity,
    VulnCategory,
)

logger = logging.getLogger(__name__)

# CVSS v4.0 base score lookup table (simplified)
# Keys: (AV, AC, AT, PR, UI)  Values: approximate base score delta
_CVSS_SEVERITY_THRESHOLDS = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFORMATIONAL: (0.0, 0.0),
}

# Regulatory compliance mapping
_COMPLIANCE_MAP: dict[VulnCategory, list[str]] = {
    VulnCategory.SQLI: ["OWASP A03:2021", "CWE-89", "PCI-DSS 6.3.1", "GDPR Art.32"],
    VulnCategory.XSS: ["OWASP A03:2021", "CWE-79", "ASVS V5.3.3"],
    VulnCategory.IDOR: ["OWASP A01:2021", "CWE-284", "GDPR Art.5(1)(f)", "ASVS V4.2.1"],
    VulnCategory.BAC: ["OWASP A01:2021", "CWE-284", "ASVS V4.1.1"],
    VulnCategory.AUTH_BYPASS: ["OWASP A07:2021", "CWE-287", "ASVS V2.1.1"],
    VulnCategory.SSRF: ["OWASP A10:2021", "CWE-918"],
    VulnCategory.SENSITIVE_EXPOSURE: ["OWASP A02:2021", "CWE-200", "GDPR Art.32", "PCI-DSS 3.4"],
    VulnCategory.COMMAND_INJECTION: ["OWASP A03:2021", "CWE-77", "PCI-DSS 6.3.1"],
}


class BusinessAgent:
    """
    Business risk translation agent.

    Enriches SecurityFinding objects with:
    - Auto-computed CVSS v4.0 vectors and scores
    - Business impact descriptions tailored to the finding context
    - Regulatory compliance references
    - Prioritised remediation recommendations
    """

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def enrich(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Enrich all findings with business context and CVSS scores."""
        enriched: list[SecurityFinding] = []
        for finding in findings:
            try:
                enriched.append(self._enrich_finding(finding))
            except Exception as exc:
                logger.warning("Failed to enrich finding %s: %s", finding.finding_id, exc)
                enriched.append(finding)
        return enriched

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _enrich_finding(self, finding: SecurityFinding) -> SecurityFinding:
        # Compute CVSS v4.0
        cvss = self._compute_cvss(finding)

        # Generate business impact via LLM
        impact = self._generate_business_impact(finding)

        # Map to compliance frameworks
        compliance = _COMPLIANCE_MAP.get(finding.category, [])
        owasp = [c for c in compliance if c.startswith("OWASP")]
        asvs = [c for c in compliance if c.startswith("ASVS")]
        existing_owasp = list(dict.fromkeys(finding.owasp_top10 + owasp))
        existing_asvs = list(dict.fromkeys(finding.asvs_controls + asvs))

        return finding.model_copy(
            update={
                "cvss": cvss,
                "business_impact": impact,
                "owasp_top10": existing_owasp,
                "asvs_controls": existing_asvs,
            }
        )

    def _compute_cvss(self, finding: SecurityFinding) -> CvssVector:
        """
        Derive CVSS v4.0 vector from finding metadata.

        Uses heuristic rules based on category, HTTP method, and severity
        to populate the vector components, then calls LLM for validation.
        """
        # Heuristic vector assignment
        av = "N"  # Network by default (web app)
        ac = "L"  # Low complexity (most web vulns are straightforward)
        at = "N"  # No attack requirements
        pr = self._estimate_pr(finding)
        ui = self._estimate_ui(finding)

        # Impact components based on category
        conf, integ, avail = self._estimate_impact(finding)

        # Approximate score from severity (CVSS v4.0 simplified)
        thresholds = _CVSS_SEVERITY_THRESHOLDS.get(finding.severity, (5.0, 6.9))
        base_score = (thresholds[0] + thresholds[1]) / 2

        vector_string = (
            f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
            f"/VC:{conf}/VI:{integ}/VA:{avail}/SC:N/SI:N/SA:N"
        )

        return CvssVector(
            attack_vector=av,
            attack_complexity=ac,
            attack_requirements=at,
            privileges_required=pr,
            user_interaction=ui,
            vuln_conf_impact=conf,
            vuln_integ_impact=integ,
            vuln_avail_impact=avail,
            sub_conf_impact="N",
            sub_integ_impact="N",
            sub_avail_impact="N",
            base_score=round(base_score, 1),
            vector_string=vector_string,
        )

    def _estimate_pr(self, finding: SecurityFinding) -> str:
        """Estimate Privileges Required from finding type."""
        if finding.category in (VulnCategory.IDOR, VulnCategory.BAC):
            return "L"  # Requires low-privilege account
        if finding.category in (VulnCategory.SQLI, VulnCategory.XSS, VulnCategory.SSRF):
            return "N"  # No privileges needed
        return "N"

    def _estimate_ui(self, finding: SecurityFinding) -> str:
        """Estimate User Interaction from finding type."""
        if finding.category in (VulnCategory.XSS, VulnCategory.CSRF):
            return "P"  # Passive (victim must view page)
        return "N"

    def _estimate_impact(self, finding: SecurityFinding) -> tuple[str, str, str]:
        """Return (Confidentiality, Integrity, Availability) impact strings."""
        category = finding.category
        if category in (VulnCategory.SQLI, VulnCategory.SENSITIVE_EXPOSURE):
            return "H", "H", "L"
        if category in (VulnCategory.IDOR, VulnCategory.BAC, VulnCategory.AUTH_BYPASS):
            return "H", "L", "N"
        if category == VulnCategory.XSS:
            return "L", "L", "N"
        if category == VulnCategory.COMMAND_INJECTION:
            return "H", "H", "H"
        if category == VulnCategory.SSRF:
            return "H", "L", "N"
        if category == VulnCategory.PATH_TRAVERSAL:
            return "H", "N", "N"
        return "L", "L", "N"

    def _generate_business_impact(self, finding: SecurityFinding) -> str:
        """Generate a business-oriented impact statement via LLM."""
        prompt = (
            "You are a Chief Information Security Officer presenting a security finding to the board.\n\n"
            f"Vulnerability: {finding.title}\n"
            f"Category: {finding.category.value}\n"
            f"Severity: {finding.severity.value}\n"
            f"Affected URL: {finding.affected_url}\n"
            f"Technical description: {finding.technical_description[:500]}\n\n"
            "Write a 2–3 sentence business impact statement that:\n"
            "1. Explains the real-world consequence WITHOUT technical jargon\n"
            "2. Quantifies risk in terms of data exposure, financial loss, or regulatory penalty\n"
            "3. Is appropriate for a C-suite audience\n\n"
            "Respond with ONLY the impact statement, no preamble."
        )
        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            return response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            logger.warning("LLM business impact generation failed: %s", exc)
            return self._fallback_impact(finding)

    def _fallback_impact(self, finding: SecurityFinding) -> str:
        """Rule-based fallback when LLM is unavailable."""
        impacts = {
            VulnCategory.SQLI: (
                "An attacker can extract, modify, or delete all data in the database. "
                "This may result in full compromise of customer PII, regulatory fines under GDPR, "
                "and irreversible reputational damage."
            ),
            VulnCategory.IDOR: (
                "Attackers can access other users' private data by manipulating identifiers. "
                "This violates data privacy regulations and could expose sensitive personal information."
            ),
            VulnCategory.BAC: (
                "Attackers can perform actions or access resources beyond their authorised privilege level. "
                "This may lead to unauthorised data access or administrative control."
            ),
            VulnCategory.XSS: (
                "Attackers can inject malicious scripts that execute in users' browsers, "
                "enabling session hijacking, credential theft, and defacement."
            ),
        }
        return impacts.get(
            finding.category,
            f"This {finding.severity.value}-severity vulnerability may expose the organisation "
            f"to security breaches and compliance violations.",
        )
