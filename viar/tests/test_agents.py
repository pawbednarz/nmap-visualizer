"""Tests for the multi-agent system."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from viar.agents.exploitation_agent import ExploitationAgent
from viar.agents.business_agent import BusinessAgent
from viar.agents.qa_agent import QAAgent
from viar.core.synchronizer.burp_video_sync import SyncResult
from viar.models.finding import SecurityFinding, Severity, VulnCategory


class TestExploitationAgent:
    def test_classifies_sqli_from_scanner_issue(self, sample_burp_scan, mock_llm):
        agent = ExploitationAgent(mock_llm)
        sync = SyncResult()
        findings = agent.analyse(sample_burp_scan, sync)
        sqli_findings = [f for f in findings if f.category == VulnCategory.SQLI]
        assert len(sqli_findings) >= 1

    def test_heuristic_detects_sqli_payload(self, sample_burp_scan, mock_llm):
        agent = ExploitationAgent(mock_llm)
        sync = SyncResult()
        findings = agent.analyse(sample_burp_scan, sync)
        # SQL payload in the login request body should trigger heuristic
        assert any(f.category == VulnCategory.SQLI for f in findings)

    def test_deduplicates_findings(self, sample_burp_scan, mock_llm):
        agent = ExploitationAgent(mock_llm)
        sync = SyncResult()
        findings = agent.analyse(sample_burp_scan, sync)
        # No two findings should have same category + URL
        keys = [(f.category, f.affected_url) for f in findings]
        assert len(keys) == len(set(keys))

    def test_classify_issue_name_maps_correctly(self, mock_llm):
        agent = ExploitationAgent(mock_llm)
        assert agent._classify_issue_name("SQL injection") == VulnCategory.SQLI
        assert agent._classify_issue_name("Cross-site scripting") == VulnCategory.XSS
        assert agent._classify_issue_name("IDOR access control") == VulnCategory.BAC


class TestBusinessAgent:
    def test_computes_cvss_vector(self, sample_finding, mock_llm):
        agent = BusinessAgent(mock_llm)
        enriched = agent.enrich([sample_finding])
        assert len(enriched) == 1
        assert enriched[0].cvss is not None
        assert 0 < enriched[0].cvss.base_score <= 10

    def test_generates_business_impact(self, sample_finding, mock_llm):
        mock_llm.invoke.return_value.content = "Attackers can access all user accounts."
        agent = BusinessAgent(mock_llm)
        enriched = agent.enrich([sample_finding])
        assert enriched[0].business_impact != ""

    def test_maps_owasp_controls(self, sample_finding, mock_llm):
        agent = BusinessAgent(mock_llm)
        enriched = agent.enrich([sample_finding])
        # SQLI should map to OWASP A03:2021
        assert any("A03" in owasp for owasp in enriched[0].owasp_top10)

    def test_critical_finding_has_high_cvss(self, mock_llm):
        from viar.models.finding import SecurityFinding, Severity, VulnCategory
        import uuid
        critical_finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            title="Remote Code Execution",
            category=VulnCategory.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            affected_url="http://example.com/exec",
            technical_description="Command injection vulnerability",
        )
        agent = BusinessAgent(mock_llm)
        enriched = agent.enrich([critical_finding])
        # Critical severity should map to high CVSS
        assert enriched[0].cvss.base_score >= 7.0


class TestQAAgent:
    def test_flags_finding_without_evidence(self, mock_llm):
        import uuid
        from viar.models.finding import SecurityFinding, Severity, VulnCategory
        finding_no_evidence = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            title="Speculative Finding",
            category=VulnCategory.OTHER,
            severity=Severity.MEDIUM,
            affected_url="http://example.com/speculative",
        )
        agent = QAAgent(mock_llm)
        reviewed = agent.review([finding_no_evidence])
        assert reviewed[0].hallucination_risk > 0.5
        assert not reviewed[0].qa_verified

    def test_passes_finding_with_evidence(self, sample_finding, mock_llm):
        mock_llm.invoke.return_value.content = "No issues found."
        agent = QAAgent(mock_llm)
        reviewed = agent.review([sample_finding])
        # Finding has evidence_request and evidence_response
        assert reviewed[0].hallucination_risk < 0.5

    def test_enriches_remediation_with_asvs(self, sample_finding, mock_llm):
        agent = QAAgent(mock_llm)
        reviewed = agent.review([sample_finding])
        # SQLI finding should get ASVS V5.3.4 guidance
        assert "ASVS" in reviewed[0].remediation or "parameterised" in reviewed[0].remediation.lower()

    def test_flags_implausible_cvss(self, mock_llm):
        import uuid
        from viar.models.finding import SecurityFinding, Severity, VulnCategory, CvssVector
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            title="Critical with low CVSS",
            category=VulnCategory.SQLI,
            severity=Severity.CRITICAL,
            affected_url="http://example.com/",
            cvss=CvssVector(
                attack_vector="N", attack_complexity="L", attack_requirements="N",
                privileges_required="N", user_interaction="N",
                vuln_conf_impact="H", vuln_integ_impact="H", vuln_avail_impact="H",
                sub_conf_impact="N", sub_integ_impact="N", sub_avail_impact="N",
                base_score=3.0,  # Implausibly low for Critical
                vector_string="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            ),
        )
        agent = QAAgent(mock_llm)
        reviewed = agent.review([finding])
        assert reviewed[0].qa_notes and "CVSS" in reviewed[0].qa_notes


class TestPIIScrubber:
    def test_scrubs_email(self):
        from viar.core.security import PIIScrubber
        scrubber = PIIScrubber()
        result = scrubber.scrub("Contact: john.doe@example.com for support")
        assert "john.doe@example.com" not in result
        assert "[EMAIL]" in result

    def test_scrubs_credit_card(self):
        from viar.core.security import PIIScrubber
        scrubber = PIIScrubber()
        result = scrubber.scrub("Payment: 4111-1111-1111-1111 processed")
        assert "4111" not in result
        assert "[CREDIT_CARD]" in result

    def test_scrubs_jwt(self):
        from viar.core.security import PIIScrubber
        scrubber = PIIScrubber()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = scrubber.scrub(f"Token: {jwt}")
        assert jwt not in result
        assert "[JWT_TOKEN]" in result

    def test_does_not_scrub_benign_text(self):
        from viar.core.security import PIIScrubber
        scrubber = PIIScrubber()
        text = "The application returned HTTP 200 OK with a JSON body."
        assert scrubber.scrub(text) == text
