"""
Attack Chain builder — connects individual findings into multi-step attack paths.

Detects when smaller vulnerabilities can be chained together to form a
more serious, end-to-end attack scenario.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from viar.models.finding import AttackChain, AttackStep, SecurityFinding, Severity, VulnCategory

logger = logging.getLogger(__name__)

# Vulnerability combinations that commonly chain together
_CHAIN_PATTERNS: list[tuple[list[VulnCategory], str, str]] = [
    (
        [VulnCategory.AUTH_BYPASS, VulnCategory.IDOR],
        "Authentication Bypass → Unauthorised Data Access",
        "An attacker bypasses authentication controls and subsequently accesses "
        "data belonging to other users, combining two weaknesses into a full account takeover.",
    ),
    (
        [VulnCategory.XSS, VulnCategory.CSRF],
        "XSS → CSRF Token Theft → Authenticated Action",
        "A stored XSS payload is used to steal a victim's CSRF token, which is then "
        "used to perform unauthorised state-changing actions on their behalf.",
    ),
    (
        [VulnCategory.IDOR, VulnCategory.SENSITIVE_EXPOSURE],
        "IDOR → Sensitive Data Exfiltration",
        "An IDOR vulnerability allows an attacker to iterate over user identifiers, "
        "exfiltrating sensitive personal data for each account.",
    ),
    (
        [VulnCategory.SQLI, VulnCategory.BAC],
        "SQL Injection → Privilege Escalation",
        "SQL injection is used to read or modify the application's authorisation data, "
        "allowing the attacker to elevate their privileges to administrator level.",
    ),
    (
        [VulnCategory.SSRF, VulnCategory.SENSITIVE_EXPOSURE],
        "SSRF → Internal Service Access → Data Exfiltration",
        "Server-Side Request Forgery enables the attacker to pivot to internal services "
        "not exposed to the internet, retrieving sensitive configuration or data.",
    ),
]


class AttackChainBuilder:
    """
    Detects and builds attack chains from a list of SecurityFindings.

    Uses pattern matching to identify known chaining scenarios, then uses
    an LLM to generate a narrative for each discovered chain.
    """

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def build(self, findings: list[SecurityFinding]) -> list[AttackChain]:
        """Identify attack chains among the findings."""
        categories_present = {f.category for f in findings}
        chains: list[AttackChain] = []

        for pattern_categories, chain_title, chain_summary in _CHAIN_PATTERNS:
            matching = [c for c in pattern_categories if c in categories_present]
            if len(matching) == len(pattern_categories):
                chain = self._build_chain(
                    findings=findings,
                    categories=pattern_categories,
                    title=chain_title,
                    summary=chain_summary,
                )
                chains.append(chain)

        # LLM-based novel chain detection
        if findings and len(findings) >= 3:
            novel = self._detect_novel_chains(findings)
            chains.extend(novel)

        logger.info("AttackChainBuilder identified %d attack chains", len(chains))
        return chains

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _build_chain(
        self,
        findings: list[SecurityFinding],
        categories: list[VulnCategory],
        title: str,
        summary: str,
    ) -> AttackChain:
        # Map categories to findings
        category_to_finding: dict[VulnCategory, SecurityFinding] = {}
        for f in findings:
            if f.category in categories and f.category not in category_to_finding:
                category_to_finding[f.category] = f

        steps: list[AttackStep] = []
        finding_ids: list[str] = []
        max_severity = Severity.LOW

        for step_num, category in enumerate(categories, 1):
            f = category_to_finding.get(category)
            if not f:
                continue
            finding_ids.append(f.finding_id)
            if list(Severity).index(f.severity) < list(Severity).index(max_severity):
                max_severity = f.severity

            steps.append(
                AttackStep(
                    step_number=step_num,
                    finding_id=f.finding_id,
                    action=f"Exploit {f.title}",
                    precondition=steps[-1].result if steps else None,
                    result=f"Attacker gains {self._step_result(f.category)}",
                    burp_item_id=f.burp_issue_ids[0] if f.burp_issue_ids else None,
                )
            )

        # Generate narrative via LLM
        narrative = self._generate_narrative(title, steps, summary)

        # Combined CVSS: max of individual scores
        cvss_scores = [f.cvss.base_score for f in findings if f.cvss and f.category in categories]
        combined_score = max(cvss_scores) if cvss_scores else None

        return AttackChain(
            chain_id=str(uuid.uuid4()),
            title=title,
            severity=max_severity,
            summary=summary,
            steps=steps,
            findings=finding_ids,
            combined_cvss_score=combined_score,
            narrative=narrative,
        )

    def _step_result(self, category: VulnCategory) -> str:
        results = {
            VulnCategory.AUTH_BYPASS: "unauthenticated access to protected resources",
            VulnCategory.IDOR: "access to another user's data",
            VulnCategory.XSS: "script execution in victim's browser",
            VulnCategory.CSRF: "ability to perform actions as the victim",
            VulnCategory.SQLI: "read/write access to the database",
            VulnCategory.SSRF: "access to internal network resources",
            VulnCategory.BAC: "elevated privileges",
            VulnCategory.SENSITIVE_EXPOSURE: "exfiltrated sensitive data",
        }
        return results.get(category, "further access")

    def _generate_narrative(
        self, title: str, steps: list[AttackStep], summary: str
    ) -> str:
        if not steps:
            return summary

        step_text = "\n".join(
            f"Step {s.step_number}: {s.action} → {s.result}" for s in steps
        )
        prompt = (
            f"You are a senior penetration tester writing an attack chain narrative.\n\n"
            f"Chain: {title}\n"
            f"Steps:\n{step_text}\n\n"
            "Write a 2-paragraph narrative that explains this attack chain as a story. "
            "Paragraph 1: Technical explanation for security engineers. "
            "Paragraph 2: Business risk explanation for management. "
            "Be specific and avoid generic statements."
        )
        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            return response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            logger.warning("LLM chain narrative failed: %s", exc)
            return summary

    def _detect_novel_chains(
        self, findings: list[SecurityFinding]
    ) -> list[AttackChain]:
        """Ask LLM to identify non-template attack chains."""
        finding_summary = "\n".join(
            f"- ID:{f.finding_id[:8]} [{f.severity.value}] {f.title} ({f.category.value}) @ {f.affected_url}"
            for f in findings[:15]
        )
        prompt = (
            "You are a senior penetration tester. "
            "Review these security findings and identify any non-obvious attack chains "
            "that combine 2+ findings into a more serious scenario.\n\n"
            f"Findings:\n{finding_summary}\n\n"
            "Respond with JSON: "
            '{"chains": [{"title": str, "severity": "critical|high|medium", '
            '"finding_ids": [str], "narrative": str}]}'
            "\nOnly include chains with clear logical connection. Return empty list if none."
        )
        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            text = response.content if hasattr(response, "content") else str(response)
            return self._parse_llm_chains(text, findings)
        except Exception as exc:
            logger.debug("LLM novel chain detection failed: %s", exc)
            return []

    def _parse_llm_chains(
        self, text: str, findings: list[SecurityFinding]
    ) -> list[AttackChain]:
        import json, re
        finding_map = {f.finding_id[:8]: f for f in findings}
        chains: list[AttackChain] = []
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return chains
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return chains

        severity_map = {s.value: s for s in Severity}

        for c in data.get("chains", []):
            severity = severity_map.get(c.get("severity", "medium"), Severity.MEDIUM)
            finding_ids = [fid[:8] for fid in c.get("finding_ids", [])]
            matched_findings = [finding_map[fid] for fid in finding_ids if fid in finding_map]
            chains.append(
                AttackChain(
                    chain_id=str(uuid.uuid4()),
                    title=c.get("title", "Novel Attack Chain"),
                    severity=severity,
                    summary=c.get("narrative", ""),
                    findings=[f.finding_id for f in matched_findings],
                    narrative=c.get("narrative", ""),
                )
            )
        return chains
