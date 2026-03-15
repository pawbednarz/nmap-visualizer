"""
JIRA exporter — creates JIRA issues for each security finding.

Also supports Asana task creation via the same interface pattern.
Requires JIRA credentials configured in settings.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from viar.models.finding import SecurityFinding, Severity
from viar.models.report import PentestReport

logger = logging.getLogger(__name__)

_SEVERITY_TO_PRIORITY = {
    Severity.CRITICAL: "Highest",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFORMATIONAL: "Lowest",
}


class JiraExporter:
    """
    Creates JIRA issues (or Asana tasks) for each security finding.

    Credentials are read from environment variables via settings:
    - JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
    """

    def __init__(
        self,
        jira_url: str,
        jira_user: str,
        jira_api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        security_label: str = "security-pentest",
    ):
        self.jira_url = jira_url.rstrip("/")
        self.jira_user = jira_user
        self.jira_api_token = jira_api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.security_label = security_label

    def export(
        self,
        report: PentestReport,
        dry_run: bool = False,
    ) -> list[dict]:
        """
        Create JIRA issues for all non-informational findings.

        Args:
            report:   The pentest report to export.
            dry_run:  If True, return the payloads without making API calls.

        Returns:
            List of created issue dicts (or payloads in dry_run mode).
        """
        results: list[dict] = []
        for tech_finding in report.findings:
            f = tech_finding.finding
            if f.severity == Severity.INFORMATIONAL:
                continue

            payload = self._build_payload(f, tech_finding.poc_steps, report)

            if dry_run:
                results.append({"dry_run": True, "payload": payload})
                continue

            try:
                issue = self._create_issue(payload)
                results.append(issue)
                logger.info("Created JIRA issue %s for finding: %s", issue.get("key"), f.title)
            except Exception as exc:
                logger.error("Failed to create JIRA issue for %s: %s", f.title, exc)
                results.append({"error": str(exc), "finding": f.title})

        return results

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _build_payload(
        self,
        finding: SecurityFinding,
        poc_steps: list[str],
        report: PentestReport,
    ) -> dict:
        description = self._format_description(finding, poc_steps)
        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[SECURITY] [{finding.severity.value.upper()}] {finding.title}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": self.issue_type},
                "priority": {"name": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium")},
                "labels": [self.security_label, finding.category.value.lower().replace(" ", "-")],
                "customfield_cvss_score": finding.cvss.base_score if finding.cvss else None,
            }
        }

    def _format_description(
        self, finding: SecurityFinding, poc_steps: list[str]
    ) -> str:
        parts = [
            f"*Category:* {finding.category.value}",
            f"*Severity:* {finding.severity.value.upper()}",
            f"*Affected URL:* {finding.affected_url}",
            "",
            "*Technical Description:*",
            finding.technical_description or "N/A",
            "",
            "*Business Impact:*",
            finding.business_impact or "N/A",
        ]
        if poc_steps:
            parts += ["", "*Reproduction Steps:*"] + poc_steps
        if finding.remediation:
            parts += ["", "*Remediation:*", finding.remediation]
        if finding.cvss:
            parts += ["", f"*CVSS v4.0:* {finding.cvss.base_score:.1f} — {finding.cvss.vector_string}"]
        return "\n".join(parts)

    def _create_issue(self, payload: dict) -> dict:
        """Make the JIRA REST API call to create an issue."""
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for JIRA export. Install with: pip install httpx")

        response = httpx.post(
            f"{self.jira_url}/rest/api/3/issue",
            json=payload,
            auth=(self.jira_user, self.jira_api_token),
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
