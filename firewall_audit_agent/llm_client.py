"""Real OpenAI-compatible LLM client (httpx) plus a clearly labelled
offline explainer.

The offline explainer is NOT an LLM call. It drafts only from the
retrieved guidance and the classifier output, and every caller must
record llm_mode="offline" when it is used.
"""
from __future__ import annotations

import os

import httpx

from .models import FirewallRule, GuidanceCitation


class OpenAICompatibleClient:
    """Working OpenAI-compatible chat client.

    Env: OPENAI_API_KEY, OPENAI_BASE_URL (default https://api.openai.com/v1),
    LLM_MODEL (default gpt-4o-mini). Swappable to Ollama / Azure by
    setting OPENAI_BASE_URL, e.g. http://localhost:11434/v1 for Ollama.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 60.0,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self._client = httpx.Client(transport=transport, timeout=timeout)

    def chat(self, messages: list[dict]) -> str:
        response = self._client.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "messages": messages, "temperature": 0},
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def explain_finding(self, rule: FirewallRule, risk: str, severity: str, citations: list[GuidanceCitation]) -> str:
        cited = "\n".join(f"- {c.title}: {c.snippet}" for c in citations) or "- (no guidance retrieved)"
        messages = [
            {"role": "system", "content": "You audit firewall rules. Use only the guidance provided. Be concise and specific."},
            {
                "role": "user",
                "content": (
                    f"Rule {rule.id}: {rule.action} {rule.protocol} port {rule.port} "
                    f"from {rule.source} to {rule.dest}. {rule.description}\n"
                    f"Risk: {risk}, severity: {severity}.\nGuidance:\n{cited}\n"
                    "Draft a 2-3 sentence finding and a proposed least-privilege fix."
                ),
            },
        ]
        return self.chat(messages)


def offline_explain(rule: FirewallRule, risk: str, severity: str, citations: list[GuidanceCitation]) -> str:
    """Deterministic offline draft. Labelled offline everywhere it is used."""
    titles = ", ".join(c.title for c in citations) if citations else "no guidance retrieved"
    if risk == "risky":
        return (
            f"[OFFLINE DRAFT — not an LLM call] Rule {rule.id} ({rule.action} {rule.protocol} "
            f"port {rule.port} from {rule.source} to {rule.dest}) is {risk} ({severity}). "
            f"Guidance consulted: {titles}. "
            "Proposed fix: narrow the source to the specific host or network that needs this service, "
            "keep only the required port, and add logging; have a human review and approve the change first."
        )
    return (
        f"[OFFLINE DRAFT — not an LLM call] Rule {rule.id} ({rule.action} {rule.protocol} "
        f"port {rule.port} from {rule.source} to {rule.dest}) is {risk} ({severity}). "
        f"Guidance consulted: {titles}. No change is proposed; keep the rule under normal review."
    )
