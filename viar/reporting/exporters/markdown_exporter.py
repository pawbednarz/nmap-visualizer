"""Markdown exporter for VIAR reports."""
from __future__ import annotations

from pathlib import Path

from viar.models.finding import Severity
from viar.models.report import PentestReport

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFORMATIONAL: "⚪",
}


class MarkdownExporter:
    """Exports a PentestReport to a Markdown document."""

    def export(self, report: PentestReport, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.write_text(self._render(report), encoding="utf-8")
        return output_path

    def render_string(self, report: PentestReport) -> str:
        return self._render(report)

    def _render(self, report: PentestReport) -> str:
        sections: list[str] = []

        # Cover
        sections.append(
            f"# {report.title}\n\n"
            f"**Client:** {report.client_name}  \n"
            f"**Engagement:** {report.engagement_type}  \n"
            f"**Test Period:** {report.test_period_start.date()} – {report.test_period_end.date()}  \n"
            f"**Generated:** {report.generated_at.date()} by {report.generated_by}  \n"
            f"**Overall Risk:** {report.overall_risk_rating.value.upper() if report.overall_risk_rating else 'N/A'}  \n"
        )

        # Executive Summary
        if report.executive_summary:
            es = report.executive_summary
            sections.append(
                f"---\n\n## Executive Summary\n\n"
                f"**{es.headline}**\n\n"
                f"{es.narrative}\n\n"
                f"### Risk Overview\n\n"
                f"{es.risk_overview}\n\n"
                f"### Top Risks\n\n"
                + "\n".join(f"- {r}" for r in es.top_risks)
                + "\n\n### Recommended Priorities\n\n"
                + "\n".join(f"{p}" for p in es.recommended_priorities)
            )

        # Findings
        sections.append("---\n\n## Findings\n")
        for tech in report.findings:
            f = tech.finding
            sev_icon = _SEV_EMOJI.get(f.severity, "")
            cvss_str = (
                f"CVSS {f.cvss.base_score:.1f} · {f.cvss.vector_string}"
                if f.cvss else "N/A"
            )

            finding_md = (
                f"\n### {sev_icon} [{f.severity.value.upper()}] {f.title}\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Category | {f.category.value} |\n"
                f"| CVSS Score | {cvss_str} |\n"
                f"| Affected URL | `{f.affected_url}` |\n"
                f"| CWE | {', '.join(str(c) for c in f.cwe_ids) or 'N/A'} |\n"
                f"| OWASP | {', '.join(f.owasp_top10) or 'N/A'} |\n\n"
                f"**Technical Description**\n\n{f.technical_description}\n\n"
                f"**Business Impact**\n\n{f.business_impact or '_Not assessed._'}\n\n"
            )

            if tech.poc_steps:
                finding_md += "**Reproduction Steps**\n\n" + "\n".join(tech.poc_steps) + "\n\n"

            if tech.request_diff:
                finding_md += f"**Request Diff**\n\n```diff\n{tech.request_diff}\n```\n\n"

            if tech.remediation_snippets:
                finding_md += "**Remediation**\n\n"
                for snippet in tech.remediation_snippets:
                    finding_md += (
                        f"_{snippet.description}_\n\n"
                        f"```{snippet.language}\n{snippet.fixed_code}\n```\n\n"
                    )
            elif f.remediation:
                finding_md += f"**Remediation**\n\n{f.remediation}\n\n"

            if f.qa_notes:
                finding_md += f"> **QA Note:** {f.qa_notes}\n\n"

            sections.append(finding_md)

        # Attack Chains
        if report.attack_chains:
            chains_md = "---\n\n## Attack Chains\n\n"
            for chain in report.attack_chains:
                chains_md += (
                    f"### {chain.title}\n\n"
                    f"**Severity:** {chain.severity.value.upper()}  \n"
                    f"**Combined CVSS:** {chain.combined_cvss_score or 'N/A'}  \n\n"
                    f"{chain.narrative}\n\n"
                    f"**Attack Steps:**\n\n"
                    + "\n".join(
                        f"{s.step_number}. **{s.action}** → {s.result}"
                        for s in chain.steps
                    )
                    + "\n\n"
                )
            sections.append(chains_md)

        # Remediation Roadmap
        if report.remediation_roadmap:
            roadmap_md = "---\n\n## Remediation Roadmap\n\n| Priority | Finding | Severity | Effort | Action |\n|---|---|---|---|---|\n"
            for item in report.remediation_roadmap:
                roadmap_md += (
                    f"| {item['priority']} | {item['finding']} | "
                    f"{item['severity']} | {item['effort']} | {item['action']} |\n"
                )
            sections.append(roadmap_md)

        return "\n".join(sections)
