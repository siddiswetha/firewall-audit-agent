"""Core unit tests: rules, guidance, retrieval, classifier, LLM client."""
from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from firewall_audit_agent.classifier import RiskClassifier
from firewall_audit_agent.embeddings_store import keyword_search, load_guidance_docs
from firewall_audit_agent.llm_client import OpenAICompatibleClient, offline_explain
from firewall_audit_agent.models import FirewallRule
from firewall_audit_agent.rules import get_rule, heuristic_risk, load_rules


def test_rules_load_count():
    rules = load_rules()
    assert len(rules) == 60
    assert len({r.id for r in rules}) == 60


def test_rule_parse_invalid_action():
    with pytest.raises(ValidationError):
        FirewallRule(id="X", source="10.0.0.1", dest="10.0.0.2", port=80, protocol="TCP", action="permit")


def test_get_rule_unknown():
    with pytest.raises(KeyError):
        get_rule("RULE-999")


def test_heuristic_risk_open_ssh():
    rule = get_rule("RULE-002")  # SSH open to the internet
    risk, severity = heuristic_risk(rule)
    assert risk == "risky" and severity == "high"


def test_heuristic_risk_single_host_ssh_safe():
    rule = get_rule("RULE-001")  # SSH from a single operator host
    risk, severity = heuristic_risk(rule)
    assert risk == "safe" and severity == "low"


def test_guidance_docs_count():
    docs = load_guidance_docs()
    assert len(docs) >= 12
    assert all(d["title"] and d["text"] for d in docs)


def test_keyword_baseline_returns_docs():
    docs = load_guidance_docs()
    hits = keyword_search("Is allowing SSH from the internet risky?", docs, k=3)
    assert hits
    assert any("admin" in h["title"].lower() or "SSH" in h["text"] for h in hits)


def test_retrieval_returns_citations(guidance_store):
    citations = guidance_store.retrieve("Is allowing SSH from the internet risky?", k=3)
    assert len(citations) == 3
    assert all(c.id and c.title and c.snippet for c in citations)


def test_offline_explain_labels_offline():
    rule = get_rule("RULE-002")
    text = offline_explain(rule, "risky", "high", [])
    assert "OFFLINE" in text and "not an LLM" in text
    assert "RULE-002" in text


def test_llm_client_mocked_http():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        return httpx.Response(200, json={"choices": [{"message": {"content": "Mocked finding: narrow the source."}}]})

    client = OpenAICompatibleClient(api_key="test-key", base_url="https://example.test/v1",
                                    transport=httpx.MockTransport(handler))
    assert client.chat([{"role": "user", "content": "hi"}]) == "Mocked finding: narrow the source."


def test_llm_client_http_error_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad key"})

    client = OpenAICompatibleClient(api_key="bad", base_url="https://example.test/v1",
                                    transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        client.chat([{"role": "user", "content": "hi"}])


def test_classifier_fallback_when_no_model(tmp_path):
    clf = RiskClassifier(model_dir=tmp_path / "no-such-model")
    assert clf.available is False
    rule = get_rule("RULE-002")
    label, _conf = clf.predict(rule)
    assert label == "risky"
