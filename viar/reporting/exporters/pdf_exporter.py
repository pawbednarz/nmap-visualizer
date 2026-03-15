"""
PDF exporter using WeasyPrint (HTML → PDF) for branded report output.

Falls back to a plain-text PDF if WeasyPrint is not installed.
"""
from __future__ import annotations

import logging
from pathlib import Path

from viar.models.report import PentestReport
from .markdown_exporter import MarkdownExporter

logger = logging.getLogger(__name__)

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  :root {{ --accent: #00d4ff; --danger: #ff4444; --warn: #ff6b35; --ok: #00ff88; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #fff; color: #1a1a2e; margin: 0; padding: 0; }}
  .cover {{ background: #0d1117; color: #fff; padding: 80px 60px; min-height: 100vh; }}
  .cover h1 {{ font-size: 2.5rem; color: var(--accent); margin-bottom: 12px; }}
  .cover .meta {{ color: #8b949e; margin-top: 40px; }}
  .section {{ padding: 40px 60px; border-bottom: 1px solid #e1e4e8; }}
  h2 {{ color: #0d1117; border-left: 4px solid var(--accent); padding-left: 12px; }}
  h3 {{ color: #24292f; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
  .critical {{ background: #ff4444; color: #fff; }}
  .high {{ background: #ff6b35; color: #fff; }}
  .medium {{ background: #f0c040; color: #000; }}
  .low {{ background: #4fc3f7; color: #000; }}
  .informational {{ background: #9e9e9e; color: #fff; }}
  pre, code {{ background: #f6f8fa; padding: 4px 8px; border-radius: 4px; font-size: 0.85rem; }}
  pre {{ padding: 16px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ background: #0d1117; color: #fff; padding: 8px 12px; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e1e4e8; }}
  .page-break {{ page-break-after: always; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


class PdfExporter:
    """
    Exports a PentestReport to a branded PDF.

    Uses WeasyPrint for high-quality HTML→PDF conversion.
    Falls back to saving a Markdown file if WeasyPrint is unavailable.
    """

    def __init__(self, logo_path: str | None = None):
        self.logo_path = logo_path

    def export(self, report: PentestReport, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        html = self._render_html(report)

        try:
            from weasyprint import HTML  # type: ignore[import]
            HTML(string=html).write_pdf(str(output_path))
            logger.info("PDF exported to %s", output_path)
        except ImportError:
            logger.warning("WeasyPrint not installed — saving as Markdown instead")
            md_path = output_path.with_suffix(".md")
            MarkdownExporter().export(report, md_path)
            return md_path

        return output_path

    def _render_html(self, report: PentestReport) -> str:
        from viar.models.finding import Severity
        body_parts: list[str] = []

        # Cover page
        risk_class = (report.overall_risk_rating.value if report.overall_risk_rating else "medium").lower()
        body_parts.append(
            f'<div class="cover">'
            f'<h1>{report.title}</h1>'
            f'<p class="meta"><strong>Client:</strong> {report.client_name}<br>'
            f'<strong>Engagement:</strong> {report.engagement_type}<br>'
            f'<strong>Test Period:</strong> {report.test_period_start.date()} – {report.test_period_end.date()}<br>'
            f'<strong>Generated:</strong> {report.generated_at.date()} by {report.generated_by}<br>'
            f'<strong>Overall Risk:</strong> <span class="badge {risk_class}">'
            f'{(report.overall_risk_rating.value or "N/A").upper()}</span></p>'
            f'</div><div class="page-break"></div>'
        )

        # Executive Summary
        if report.executive_summary:
            es = report.executive_summary
            body_parts.append(
                f'<div class="section"><h2>Executive Summary</h2>'
                f'<h3>{es.headline}</h3>'
                f'<p>{es.narrative.replace(chr(10), "<br>")}</p>'
                f'<h3>Risk Overview</h3><pre>{es.risk_overview}</pre>'
                f'<h3>Top Risks</h3><ul>'
                + "".join(f"<li>{r}</li>" for r in es.top_risks)
                + f"</ul><h3>Recommended Priorities</h3><ol>"
                + "".join(f"<li>{p}</li>" for p in es.recommended_priorities)
                + "</ol></div>"
            )

        # Findings
        body_parts.append('<div class="section"><h2>Findings</h2>')
        for tech in report.findings:
            f = tech.finding
            sev = f.severity.value.lower()
            cvss_str = f"{f.cvss.base_score:.1f}" if f.cvss else "N/A"
            body_parts.append(
                f'<h3><span class="badge {sev}">{f.severity.value.upper()}</span> {f.title}</h3>'
                f'<table><tr><th>Field</th><th>Value</th></tr>'
                f'<tr><td>Category</td><td>{f.category.value}</td></tr>'
                f'<tr><td>CVSS</td><td>{cvss_str}</td></tr>'
                f'<tr><td>Affected URL</td><td><code>{f.affected_url}</code></td></tr>'
                f'<tr><td>CWE</td><td>{", ".join(str(c) for c in f.cwe_ids) or "N/A"}</td></tr>'
                f'</table>'
                f'<p><strong>Technical Description:</strong><br>{f.technical_description}</p>'
                f'<p><strong>Business Impact:</strong><br>{f.business_impact or "Not assessed."}</p>'
            )
            if tech.poc_steps:
                body_parts.append(
                    "<p><strong>Reproduction Steps:</strong></p><ol>"
                    + "".join(f"<li>{s}</li>" for s in tech.poc_steps)
                    + "</ol>"
                )
            for snippet in tech.remediation_snippets:
                body_parts.append(
                    f"<p><strong>Remediation ({snippet.language}):</strong></p>"
                    f"<pre><code>{snippet.fixed_code}</code></pre>"
                )
        body_parts.append("</div>")

        body = "\n".join(body_parts)
        return _HTML_TEMPLATE.format(title=report.title, body=body)
