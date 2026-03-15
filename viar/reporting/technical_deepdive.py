"""
Technical Deep-Dive generator.

Produces formatted PoC blocks with syntax highlighting, request/response
diffs (before/after), and step-by-step reproduction instructions.
"""
from __future__ import annotations

import difflib
import logging
from typing import Any

from viar.models.finding import SecurityFinding
from viar.models.report import TechnicalFinding

logger = logging.getLogger(__name__)


class TechnicalDeepDiveGenerator:
    """Generates full technical write-ups for each security finding."""

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def generate(self, finding: SecurityFinding) -> TechnicalFinding:
        """Generate a complete TechnicalFinding from a SecurityFinding."""
        poc_steps = self._generate_poc_steps(finding)
        request_diff = self._build_request_diff(finding)
        response_diff = self._build_response_diff(finding)

        return TechnicalFinding(
            finding=finding,
            poc_steps=poc_steps,
            request_diff=request_diff,
            response_diff=response_diff,
        )

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _generate_poc_steps(self, finding: SecurityFinding) -> list[str]:
        """Generate numbered reproduction steps via LLM."""
        if finding.proof_of_concept:
            # Already have a PoC — just structure it
            return self._structure_existing_poc(finding.proof_of_concept)

        prompt = (
            "You are a senior penetration tester writing reproduction steps for a finding.\n\n"
            f"Title: {finding.title}\n"
            f"Category: {finding.category.value}\n"
            f"Affected URL: {finding.affected_url}\n"
            f"HTTP Method: {finding.http_method or 'GET'}\n\n"
            f"Evidence Request:\n```http\n{(finding.evidence_request or 'N/A')[:1000]}\n```\n\n"
            f"Evidence Response:\n```http\n{(finding.evidence_response or 'N/A')[:500]}\n```\n\n"
            "Generate 4-8 numbered, step-by-step reproduction instructions. "
            "Each step must be concrete and actionable. "
            "Include the exact payload/parameter used. "
            "Format as a JSON array of strings: [\"Step 1: ...\", \"Step 2: ...\"]"
        )

        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            text = response.content if hasattr(response, "content") else str(response)
            return self._parse_steps(text)
        except Exception as exc:
            logger.warning("LLM PoC generation failed for %s: %s", finding.finding_id, exc)
            return self._fallback_steps(finding)

    def _structure_existing_poc(self, poc: str) -> list[str]:
        """Convert a free-form PoC string into numbered steps."""
        lines = [l.strip() for l in poc.splitlines() if l.strip()]
        steps: list[str] = []
        step_num = 1
        for line in lines:
            if not line.startswith(("Step", str(step_num))):
                line = f"Step {step_num}: {line}"
            steps.append(line)
            step_num += 1
        return steps

    def _parse_steps(self, text: str) -> list[str]:
        import json, re
        match = re.search(r"\[.*?\]", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        # Fallback: split by numbered list pattern
        return re.findall(r"\d+\.\s+.+", text)

    def _fallback_steps(self, finding: SecurityFinding) -> list[str]:
        return [
            f"Step 1: Navigate to {finding.affected_url}",
            f"Step 2: Send a {finding.http_method or 'GET'} request with the payload identified in evidence",
            "Step 3: Observe the server response for indicators of exploitation",
            "Step 4: Document the response confirming the vulnerability",
        ]

    def _build_request_diff(self, finding: SecurityFinding) -> str | None:
        """Build a unified diff showing the attack request vs a benign baseline."""
        if not finding.evidence_request:
            return None

        # Simulate a 'before' (benign) request by removing obvious payload markers
        benign = self._strip_payloads(finding.evidence_request)
        if benign == finding.evidence_request:
            return None

        diff_lines = list(
            difflib.unified_diff(
                benign.splitlines(keepends=True),
                finding.evidence_request.splitlines(keepends=True),
                fromfile="benign_request.http",
                tofile="attack_request.http",
                lineterm="",
            )
        )
        return "".join(diff_lines) if diff_lines else None

    def _build_response_diff(self, finding: SecurityFinding) -> str | None:
        """Compare response to a nominal 200 OK to highlight anomalies."""
        if not finding.evidence_response:
            return None
        # For now, just return the response as-is (diff would require before/after pair)
        return finding.evidence_response[:3000]

    def _strip_payloads(self, request: str) -> str:
        """Approximate 'benign' version of a request by removing common payload chars."""
        import re
        cleaned = re.sub(r"'[^']*'", "'<value>'", request)
        cleaned = re.sub(r'"[^"]{30,}"', '"<value>"', cleaned)
        return cleaned
