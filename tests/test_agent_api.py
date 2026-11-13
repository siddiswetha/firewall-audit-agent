"""Agent and API tests: human gate, citations, /health and /audit."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firewall_audit_agent.agent import run_audit
from firewall_audit_agent.app import app
from firewall_audit_agent.classifier import RiskClassifier

ROOT = Path(__file__).resolve().parents[1]


def test_agent_human_gate_no_approval(guidance_store, tmp_path):
    clf = RiskClassifier(model_dir=tmp_path / "no-model")
    report = run_audit("RULE-002", approve=False, store=guidance_store, classifier=clf)
    assert report.finding.approved is False
    assert report.finding.status == "pending_review"
    assert "approved" not in report.finding.summary.lower() or "not" in report.finding.summary.lower()
    assert Path(report.run_path).exists()
    assert report.llm_mode == "offline"
    assert report.llm_used is False


def test_agent_human_gate_approved(guidance_store, tmp_path):
    clf = RiskClassifier(model_dir=tmp_path / "no-model")
    report = run_audit("RULE-002", approve=True, store=guidance_store, classifier=clf)
    assert report.finding.approved is True
    assert report.finding.status == "approved"


def test_agent_citations_present(guidance_store, tmp_path):
    clf = RiskClassifier(model_dir=tmp_path / "no-model")
    report = run_audit("RULE-005", approve=False, store=guidance_store, classifier=clf)
    assert len(report.finding.citations) >= 1
    assert report.finding.rule_id == "RULE-005"


def test_api_health():
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_api_audit_pending_review():
    with TestClient(app) as client:
        resp = client.post("/audit", json={"rule_id": "RULE-002", "approve": False})
        assert resp.status_code == 200
        body = resp.json()
        assert body["finding"]["approved"] is False
        assert body["finding"]["status"] == "pending_review"
        assert body["llm_mode"] == "offline"


def test_api_audit_unknown_rule():
    with TestClient(app) as client:
        resp = client.post("/audit", json={"rule_id": "RULE-999"})
        assert resp.status_code == 404


def test_lora_eval_numbers_are_real():
    path = ROOT / "evals" / "lora_eval.json"
    if not path.exists():
        pytest.skip("lora_eval.json not present — run scripts/train_lora.py first")
    data = json.loads(path.read_text())
    assert data["test_n"] == 60 and data["train_n"] == 240
    assert data["lora_fine_tuned"]["accuracy"] > data["base_untrained_head"]["accuracy"]
    assert data["lora_fine_tuned"]["accuracy"] > data["majority_baseline"]["accuracy"]


def test_retrieval_eval_numbers_are_real():
    path = ROOT / "evals" / "retrieval_eval.json"
    if not path.exists():
        pytest.skip("retrieval_eval.json not present — run scripts/eval_retrieval.py first")
    data = json.loads(path.read_text())
    assert data["n_queries"] == 12
    assert data["embedding_recall@5"] >= data["keyword_recall@5"]
