"""
ReportBuilder — assembles all agent outputs into a unified PentestReport.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from viar.models.burp import BurpScanData
from viar.models.finding import AttackChain, SecurityFinding, Severity
from viar.models.report import PentestReport, ReportSection, TechnicalFinding
from viar.core.synchronizer.burp_video_sync import SyncResult
from .executive_summary import ExecutiveSummaryGenerator
from .technical_deepdive import TechnicalDeepDiveGenerator
from .smart_remediation import SmartRemediationGenerator
from .attack_chain import AttackChainBuilder


class ReportBuilder:
    """
    Assembles a complete PentestReport from agent-reviewed findings.

    Orchestrates:
    - ExecutiveSummaryGenerator
    - TechnicalDeepDiveGenerator
    - SmartRemediationGenerator
    - AttackChainBuilder
    """

    def __init__(
        self,
        llm_client: Any,
        model: str = "claude-sonnet-4-6",
        client_name: str = "Client",
        engagement_type: str = "Web Application Penetration Test",
    ):
        self.llm = llm_client
        self.model = model
        self.client_name = client_name
        self.engagement_type = engagement_type

        self.exec_gen = ExecutiveSummaryGenerator(llm_client, model)
        self.tech_gen = TechnicalDeepDiveGenerator(llm_client, model)
        self.remediation_gen = SmartRemediationGenerator(llm_client, model)
        self.chain_builder = AttackChainBuilder(llm_client, model)

    def build(
        self,
        findings: list[SecurityFinding],
        sync_result: Optional[SyncResult] = None,
        burp_data: Optional[BurpScanData] = None,
    ) -> PentestReport:
        tech_fingerprints = burp_data.tech_fingerprints if burp_data else []
        burp_files = [burp_data.source_file] if burp_data else []

        # Executive summary
        exec_summary = self.exec_gen.generate(
            findings, self.client_name, self.engagement_type
        )

        # Technical deep-dives with remediation snippets
        technical_findings: list[TechnicalFinding] = []
        for finding in sorted(findings, key=lambda f: list(Severity).index(f.severity)):
            tech = self.tech_gen.generate(finding)
            snippets = self.remediation_gen.generate(finding, tech_fingerprints)
            tech = tech.model_copy(update={"remediation_snippets": snippets})
            technical_findings.append(tech)

        # Attack chains
        attack_chains: list[AttackChain] = self.chain_builder.build(findings)

        # Remediation roadmap (prioritised list)
        roadmap = self._build_roadmap(findings)

        # Overall risk rating
        overall_risk = exec_summary._get_overall_severity() if hasattr(exec_summary, "_get_overall_severity") else self._compute_overall_risk(findings)

        # Determine test period from Burp data
        now = datetime.utcnow()
        test_start = burp_data.time_range_start or now if burp_data else now
        test_end = burp_data.time_range_end or now if burp_data else now

        return PentestReport(
            report_id=str(uuid.uuid4()),
            title=f"{self.engagement_type} — {self.client_name}",
            client_name=self.client_name,
            engagement_type=self.engagement_type,
            test_period_start=test_start,
            test_period_end=test_end,
            burp_files=burp_files,
            executive_summary=exec_summary,
            scope=burp_data.unique_hosts if burp_data else [],
            findings=technical_findings,
            attack_chains=attack_chains,
            remediation_roadmap=roadmap,
            overall_risk_rating=overall_risk,
            sections_included=[
                ReportSection.COVER,
                ReportSection.EXECUTIVE_SUMMARY,
                ReportSection.SCOPE,
                ReportSection.FINDINGS,
                ReportSection.ATTACK_CHAINS,
                ReportSection.REMEDIATION_ROADMAP,
            ],
        )

    def _build_roadmap(self, findings: list[SecurityFinding]) -> list[dict]:
        roadmap = []
        for i, f in enumerate(
            sorted(findings, key=lambda x: list(Severity).index(x.severity)), 1
        ):
            roadmap.append(
                {
                    "priority": i,
                    "finding": f.title,
                    "severity": f.severity.value,
                    "effort": self._estimate_effort(f),
                    "action": (f.remediation or "See technical findings").split("\n")[0][:150],
                }
            )
        return roadmap

    def _estimate_effort(self, finding: SecurityFinding) -> str:
        from viar.models.finding import VulnCategory
        quick_fixes = {
            VulnCategory.XSS,
            VulnCategory.OPEN_REDIRECT,
            VulnCategory.MISCONFIG,
        }
        if finding.category in quick_fixes:
            return "Low (< 1 day)"
        if finding.severity == Severity.CRITICAL:
            return "High (1–2 weeks)"
        return "Medium (2–5 days)"

    def _compute_overall_risk(self, findings: list[SecurityFinding]) -> Severity:
        for sev in Severity:
            if any(f.severity == sev for f in findings):
                return sev
        return Severity.INFORMATIONAL
