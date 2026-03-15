"""JSON exporter — outputs DefectDojo-compatible JSON."""
from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from viar.models.report import PentestReport


def _default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class JsonExporter:
    """
    Exports PentestReport to JSON in two formats:
    - VIAR native (full report model)
    - DefectDojo import format
    """

    def export_native(self, report: PentestReport, output_path: str | Path) -> Path:
        """Export full report as VIAR-native JSON."""
        output_path = Path(output_path)
        output_path.write_text(
            json.dumps(report.model_dump(), default=_default, indent=2),
            encoding="utf-8",
        )
        return output_path

    def export_defectdojo(
        self, report: PentestReport, output_path: str | Path
    ) -> Path:
        """Export in DefectDojo Generic Findings Import format."""
        output_path = Path(output_path)
        findings_json = [
            self._to_defectdojo_finding(tf) for tf in report.findings
        ]
        output_path.write_text(
            json.dumps({"findings": findings_json}, default=_default, indent=2),
            encoding="utf-8",
        )
        return output_path

    def _to_defectdojo_finding(self, tech_finding: Any) -> dict:
        f = tech_finding.finding
        return {
            "title": f.title,
            "severity": f.severity.value.capitalize(),
            "description": f.technical_description,
            "mitigation": f.remediation or "",
            "impact": f.business_impact or "",
            "references": "\n".join(f.owasp_top10 + [f"CWE-{c}" for c in f.cwe_ids]),
            "active": True,
            "verified": f.qa_verified,
            "false_p": f.hallucination_risk > 0.7,
            "cvssv3": f.cvss.vector_string if f.cvss else "",
            "cvssv3_score": f.cvss.base_score if f.cvss else None,
            "cwe": f.cwe_ids[0] if f.cwe_ids else None,
            "url": f.affected_url,
            "steps_to_reproduce": "\n".join(tech_finding.poc_steps),
        }
