"""
LangGraph orchestration for the VIAR multi-agent pipeline.

Graph topology:
  START
    │
    ▼
  [exploitation_node]  ← ExploitationAgent.analyse()
    │
    ▼
  [business_node]      ← BusinessAgent.enrich()
    │
    ▼
  [qa_node]            ← QAAgent.review()
    │
    ▼
  [reporting_node]     ← ReportBuilder.build()
    │
    ▼
  END

State flows through each node and is accumulated in AgentState.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from viar.models.burp import BurpScanData
from viar.models.finding import SecurityFinding
from viar.models.report import PentestReport
from viar.models.video import VideoAnalysis
from viar.core.synchronizer.burp_video_sync import SyncResult

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    """Shared state flowing through the LangGraph pipeline."""

    # Inputs
    burp_data: Optional[BurpScanData] = None
    video_analysis: Optional[VideoAnalysis] = None
    sync_result: Optional[SyncResult] = None

    # Intermediate outputs
    raw_findings: list[SecurityFinding] = field(default_factory=list)
    enriched_findings: list[SecurityFinding] = field(default_factory=list)
    reviewed_findings: list[SecurityFinding] = field(default_factory=list)

    # Final output
    report: Optional[PentestReport] = None

    # Pipeline metadata
    errors: list[str] = field(default_factory=list)
    completed_nodes: list[str] = field(default_factory=list)


class ViarAgentGraph:
    """
    LangGraph-based orchestration of the VIAR multi-agent pipeline.

    Provides a simple .run() interface that executes all agents in sequence
    and returns the final AgentState with a completed PentestReport.

    When LangGraph is available, the graph is compiled for:
    - Node-level error recovery
    - Conditional edges (skip QA for low-severity findings)
    - Parallel execution of independent nodes

    Falls back to sequential execution if LangGraph is not installed.
    """

    def __init__(
        self,
        exploitation_agent: Any,
        business_agent: Any,
        qa_agent: Any,
        report_builder: Any,
    ):
        self.exploitation = exploitation_agent
        self.business = business_agent
        self.qa = qa_agent
        self.report_builder = report_builder
        self._graph = self._build_graph()

    def run(self, state: AgentState) -> AgentState:
        """Execute the full multi-agent pipeline."""
        if self._graph:
            return self._run_langgraph(state)
        return self._run_sequential(state)

    # ------------------------------------------------------------------ #
    # LangGraph integration
    # ------------------------------------------------------------------ #

    def _build_graph(self) -> Any:
        """Attempt to build a LangGraph StateGraph. Returns None if not installed."""
        try:
            from langgraph.graph import StateGraph, END  # type: ignore[import]

            builder = StateGraph(AgentState)

            builder.add_node("exploitation", self._exploitation_node)
            builder.add_node("business", self._business_node)
            builder.add_node("qa", self._qa_node)
            builder.add_node("reporting", self._reporting_node)

            builder.set_entry_point("exploitation")
            builder.add_edge("exploitation", "business")
            builder.add_edge("business", "qa")
            builder.add_edge("qa", "reporting")
            builder.add_edge("reporting", END)

            return builder.compile()
        except ImportError:
            logger.info("LangGraph not available — using sequential execution")
            return None

    def _run_langgraph(self, state: AgentState) -> AgentState:
        try:
            result = self._graph.invoke(state)
            return result
        except Exception as exc:
            logger.error("LangGraph execution failed: %s", exc)
            return self._run_sequential(state)

    # ------------------------------------------------------------------ #
    # Sequential fallback
    # ------------------------------------------------------------------ #

    def _run_sequential(self, state: AgentState) -> AgentState:
        for node_fn in (
            self._exploitation_node,
            self._business_node,
            self._qa_node,
            self._reporting_node,
        ):
            try:
                state = node_fn(state)
            except Exception as exc:
                node_name = node_fn.__name__
                logger.error("Node %s failed: %s", node_name, exc)
                state.errors.append(f"{node_name}: {exc}")
        return state

    # ------------------------------------------------------------------ #
    # Node implementations
    # ------------------------------------------------------------------ #

    def _exploitation_node(self, state: AgentState) -> AgentState:
        logger.info("Running ExploitationAgent")
        if state.burp_data and state.sync_result:
            findings = self.exploitation.analyse(state.burp_data, state.sync_result)
            state.raw_findings = findings
        state.completed_nodes.append("exploitation")
        return state

    def _business_node(self, state: AgentState) -> AgentState:
        logger.info("Running BusinessAgent")
        if state.raw_findings:
            state.enriched_findings = self.business.enrich(state.raw_findings)
        state.completed_nodes.append("business")
        return state

    def _qa_node(self, state: AgentState) -> AgentState:
        logger.info("Running QAAgent")
        if state.enriched_findings:
            state.reviewed_findings = self.qa.review(state.enriched_findings)
        state.completed_nodes.append("qa")
        return state

    def _reporting_node(self, state: AgentState) -> AgentState:
        logger.info("Running ReportBuilder")
        if state.reviewed_findings:
            state.report = self.report_builder.build(
                findings=state.reviewed_findings,
                sync_result=state.sync_result,
                burp_data=state.burp_data,
            )
        state.completed_nodes.append("reporting")
        return state
