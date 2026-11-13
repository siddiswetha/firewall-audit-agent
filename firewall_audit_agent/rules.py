"""Rule loading and parsing, plus the deterministic heuristic fallback
used when the LoRA classifier is not available."""
from __future__ import annotations

import json
from pathlib import Path

from .models import FirewallRule

ADMIN_PORTS = {22, 3389, 5432, 3306, 6379, 27017, 1433}
WEB_PORTS = {80, 443}


def load_rules(path: str | Path | None = None) -> list[FirewallRule]:
    path = Path(path) if path else Path(__file__).resolve().parents[1] / "data" / "rules.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return [FirewallRule(**item) for item in data]


def get_rule(rule_id: str, rules: list[FirewallRule] | None = None) -> FirewallRule:
    rules = rules or load_rules()
    for rule in rules:
        if rule.id == rule_id:
            return rule
    raise KeyError(f"unknown rule id: {rule_id}")


def heuristic_risk(rule: FirewallRule) -> tuple[str, str]:
    """Deterministic fallback: (risk, severity). Mirrors the data
    generation logic so the fallback and the labelled data agree."""
    if rule.action == "deny":
        return "safe", "low"
    if rule.source == "0.0.0.0/0" and rule.dest == "0.0.0.0/0":
        return "risky", "high"
    if rule.port == 0:
        return "risky", "high"
    if rule.source == "0.0.0.0/0" and rule.port in ADMIN_PORTS:
        return "risky", "high"
    if rule.source in ("0.0.0.0/0", "198.51.100.0/24") and rule.port in ADMIN_PORTS:
        return "risky", "high"
    if rule.source == "0.0.0.0/0" and rule.port not in WEB_PORTS:
        return "risky", "medium"
    if rule.source == "0.0.0.0/0" and rule.port in WEB_PORTS:
        return "safe", "low"
    if rule.source in ("10.0.0.0/8", "192.168.1.0/24") and rule.port in ADMIN_PORTS:
        return "risky", "medium"
    if rule.dest == "0.0.0.0/0":
        return "risky", "medium"
    return "safe", "low"
