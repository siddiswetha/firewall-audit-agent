"""LangGraph agent: parse_rule -> retrieve_guidance -> classify_risk
-> draft_finding -> human_review -> final_report.

human_review is an explicit approval gate. A finding is only marked
approved when the caller passes approve=True. Otherwise the proposed
fix stays a draft proposal with status pending_review — nothing is
presented as approved or applied.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, StateGraph

from .classifier import RiskClassifier
from .embeddings_store import GuidanceStore
from .llm_client import OpenAICompatibleClient, offline_explain
from .logging_utils import get_logger, new_trace_id
from .models import AuditReport, Finding, FirewallRule
from .rules import get_rule, heuristic_risk

logger = get_logger(__name__)
ROOT = Path(__file__).resolve().parents[1]


class AgentState(TypedDict, total=False):
    rule_id: str
    rule: FirewallRule
    approve: bool
    trace_id: str
    citations: list
    risk: str
    severity: str
    draft: str
    llm_used: bool
    llm_mode: str
    finding: Finding
    report: AuditReport


def build_graph(store: GuidanceStore | None = None, classifier: RiskClassifier | None = None, llm: OpenAICompatibleClient | None = None):
    store = store or GuidanceStore()
    classifier = classifier or RiskClassifier()
    # Only construct a live LLM client when a key is present; otherwise
    # the draft node uses the offline explainer and records llm_mode=offline.
    use_live_llm = bool(os.environ.get("OPENAI_API_KEY")) and llm is None
    live_llm = llm if llm is not None else (OpenAICompatibleClient() if use_live_llm else None)

    def parse_rule(state: AgentState) -> AgentState:
        rule = get_rule(state["rule_id"])
        logger.info("parse_rule", extra={"trace_id": state.get("trace_id", "")})
        return {"rule": rule}

    def retrieve_guidance(state: AgentState) -> AgentState:
        rule = state["rule"]
        query = (
            f"Firewall rule: {rule.action} {rule.protocol} port {rule.port} "
            f"from {rule.source} to {rule.dest}. {rule.description}"
        )
        citations = store.retrieve(query, k=3)
        return {"citations": citations}

    def classify_risk(state: AgentState) -> AgentState:
        rule = state["rule"]
        risk, _conf = classifier.predict(rule)
        _r, severity = heuristic_risk(rule)
        # Severity comes from the rule pattern; the classifier decides risky/safe.
        return {"risk": risk, "severity": severity}

    def draft_finding(state: AgentState) -> AgentState:
        rule = state["rule"]
        citations = state.get("citations", [])
        if live_llm is not None:
            try:
                draft = live_llm.explain_finding(rule, state["risk"], state["severity"], citations)
                return {"draft": draft, "llm_used": True, "llm_mode": "live"}
            except Exception as exc:  # fall back, and say so
                logger.info(f"live LLM failed, using offline draft: {exc}", extra={"trace_id": state.get("trace_id", "")})
        draft = offline_explain(rule, state["risk"], state["severity"], citations)
        return {"draft": draft, "llm_used": False, "llm_mode": "offline"}

    def human_review(state: AgentState) -> AgentState:
        approved = bool(state.get("approve", False))
        finding = Finding(
            rule_id=state["rule"].id,
            risk=state["risk"],
            severity=state["severity"],
            summary=state["draft"],
            proposed_fix=state["draft"],
            citations=state.get("citations", []),
            status="approved" if approved else "pending_review",
            approved=approved,
        )
        return {"finding": finding}

    def final_report(state: AgentState) -> AgentState:
        trace_id = state.get("trace_id") or new_trace_id()
        report = AuditReport(
            trace_id=trace_id,
            rule_id=state["rule"].id,
            rule=state["rule"],
            finding=state["finding"],
            llm_used=state.get("llm_used", False),
            llm_mode=state.get("llm_mode", "offline"),
        )
        runs_dir = ROOT / "runs"
        runs_dir.mkdir(exist_ok=True)
        run_path = runs_dir / f"{trace_id}.json"
        run_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        report.run_path = str(run_path)
        return {"report": report}

    graph = StateGraph(AgentState)
    graph.add_node("parse_rule", parse_rule)
    graph.add_node("retrieve_guidance", retrieve_guidance)
    graph.add_node("classify_risk", classify_risk)
    graph.add_node("draft_finding", draft_finding)
    graph.add_node("human_review", human_review)
    graph.add_node("final_report", final_report)
    graph.set_entry_point("parse_rule")
    graph.add_edge("parse_rule", "retrieve_guidance")
    graph.add_edge("retrieve_guidance", "classify_risk")
    graph.add_edge("classify_risk", "draft_finding")
    graph.add_edge("draft_finding", "human_review")
    graph.add_edge("human_review", "final_report")
    graph.add_edge("final_report", END)
    return graph.compile()


def run_audit(rule_id: str, approve: bool = False, store: GuidanceStore | None = None,
              classifier: RiskClassifier | None = None, llm: OpenAICompatibleClient | None = None) -> AuditReport:
    trace_id = new_trace_id()
    app = build_graph(store=store, classifier=classifier, llm=llm)
    result = app.invoke({"rule_id": rule_id, "approve": approve, "trace_id": trace_id})
    report: AuditReport = result["report"]
    return report
