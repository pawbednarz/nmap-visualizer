"""
Executive Summary generator using narrative storytelling techniques.

Produces a non-technical 5-paragraph narrative that a C-suite audience
can understand without any security background.
"""
from __future__ import annotations

import logging
from typing import Any

from viar.models.finding import SecurityFinding, Severity
from viar.models.report import ExecutiveSummary

logger = logging.getLogger(__name__)

_RISK_NARRATIVE_TEMPLATES = {
    Severity.CRITICAL: (
        "The assessment has uncovered {count} critical vulnerability{plural} that represent "
        "an immediate and serious threat to {client}. These findings indicate that an attacker "
        "could — with moderate skill — gain complete control over core systems, access sensitive "
        "customer data, or cause prolonged service outages."
    ),
    Severity.HIGH: (
        "The assessment identified {count} high-severity issue{plural} that require prompt "
        "attention. Left unaddressed, these vulnerabilities could be exploited to access "
        "confidential information, bypass authentication controls, or compromise user accounts."
    ),
    Severity.MEDIUM: (
        "{count} medium-severity finding{plural} present{singular} a meaningful risk that, "
        "while not immediately exploitable in isolation, could be combined with other weaknesses "
        "to form a more serious attack chain."
    ),
    Severity.LOW: (
        "{count} low-severity observation{plural} represent{singular} best-practice improvements "
        "that, while not immediately dangerous, should be addressed in the next development cycle."
    ),
}


class ExecutiveSummaryGenerator:
    """Generates narrative executive summaries for pentest reports."""

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def generate(
        self,
        findings: list[SecurityFinding],
        client_name: str,
        engagement_type: str,
    ) -> ExecutiveSummary:
        counts = self._count_by_severity(findings)
        top_risks = self._extract_top_risks(findings)

        narrative = self._generate_narrative(findings, client_name, engagement_type, counts)
        risk_overview = self._generate_risk_overview(counts, client_name)
        priorities = self._extract_priorities(findings)

        overall_severity = self._overall_severity(counts)

        return ExecutiveSummary(
            headline=self._build_headline(client_name, engagement_type, counts),
            narrative=narrative,
            risk_overview=risk_overview,
            critical_findings_count=counts.get(Severity.CRITICAL, 0),
            high_findings_count=counts.get(Severity.HIGH, 0),
            medium_findings_count=counts.get(Severity.MEDIUM, 0),
            low_findings_count=counts.get(Severity.LOW, 0),
            top_risks=top_risks,
            recommended_priorities=priorities,
        )

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _count_by_severity(
        self, findings: list[SecurityFinding]
    ) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _overall_severity(self, counts: dict[Severity, int]) -> Severity:
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            if counts.get(sev, 0) > 0:
                return sev
        return Severity.INFORMATIONAL

    def _build_headline(
        self,
        client: str,
        engagement: str,
        counts: dict[Severity, int],
    ) -> str:
        total = sum(counts.values())
        critical = counts.get(Severity.CRITICAL, 0)
        if critical > 0:
            risk = "Critical Risk Level"
        elif counts.get(Severity.HIGH, 0) > 0:
            risk = "High Risk Level"
        else:
            risk = "Medium Risk Level"
        return f"{client} — {engagement}: {total} Finding{'s' if total != 1 else ''} ({risk})"

    def _generate_narrative(
        self,
        findings: list[SecurityFinding],
        client: str,
        engagement: str,
        counts: dict[Severity, int],
    ) -> str:
        # Build context for LLM
        finding_summaries = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}: {f.business_impact[:150] if f.business_impact else f.technical_description[:150]}"
            for f in sorted(findings, key=lambda x: list(Severity).index(x.severity))[:10]
        )

        prompt = (
            f"You are a Chief Information Security Officer writing an executive summary for {client}'s board.\n\n"
            f"Engagement: {engagement}\n"
            f"Risk Overview: {counts.get(Severity.CRITICAL, 0)} critical, "
            f"{counts.get(Severity.HIGH, 0)} high, "
            f"{counts.get(Severity.MEDIUM, 0)} medium, "
            f"{counts.get(Severity.LOW, 0)} low findings\n\n"
            f"Top Findings:\n{finding_summaries}\n\n"
            "Write a 4-paragraph executive summary using the following narrative structure:\n"
            "1. Opening — State the overall security posture in clear, direct terms\n"
            "2. The Story — Describe what an attacker could realistically do with these vulnerabilities (3-5 sentences, no jargon)\n"
            "3. Business Impact — Quantify risk in terms of data, finance, and reputation\n"
            "4. Call to Action — Prioritised, actionable recommendations for leadership\n\n"
            "Tone: Authoritative but not alarmist. Professional. No bullet points — paragraphs only."
        )

        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            return response.content if hasattr(response, "content") else str(response)
        except Exception as exc:
            logger.warning("LLM narrative generation failed: %s", exc)
            return self._fallback_narrative(client, counts)

    def _fallback_narrative(
        self, client: str, counts: dict[Severity, int]
    ) -> str:
        parts: list[str] = []
        for severity, template in _RISK_NARRATIVE_TEMPLATES.items():
            count = counts.get(severity, 0)
            if count > 0:
                plural = "ies" if count > 1 else "y" if severity == Severity.CRITICAL else "s"
                singular = "" if count > 1 else "s"
                parts.append(
                    template.format(
                        count=count,
                        plural=plural,
                        singular=singular,
                        client=client,
                    )
                )
        return "\n\n".join(parts) if parts else "No significant findings were identified."

    def _generate_risk_overview(
        self, counts: dict[Severity, int], client: str
    ) -> str:
        total = sum(counts.values())
        if total == 0:
            return f"{client}'s application demonstrated strong security posture with no findings."
        lines = [f"Total findings: {total}"]
        for sev in Severity:
            c = counts.get(sev, 0)
            if c > 0:
                lines.append(f"  • {sev.value.capitalize()}: {c}")
        return "\n".join(lines)

    def _extract_top_risks(self, findings: list[SecurityFinding]) -> list[str]:
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        return [f"{f.title} ({f.affected_url})" for f in critical_high[:5]]

    def _extract_priorities(self, findings: list[SecurityFinding]) -> list[str]:
        priorities: list[str] = []
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        for i, f in enumerate(critical_high[:5], 1):
            short_remediation = (f.remediation or "See technical detail").split("\n")[0][:100]
            priorities.append(f"{i}. {f.title}: {short_remediation}")
        return priorities
