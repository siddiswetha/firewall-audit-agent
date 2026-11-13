"""Pydantic models for rules, findings, and audit runs."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class FirewallRule(BaseModel):
    id: str
    source: str
    dest: str
    port: int = Field(ge=0, le=65535)
    protocol: str = "TCP"
    action: str
    description: str = ""
    label: str = ""  # risky / safe, when known (synthetic ground truth)
    severity: str = ""  # high / medium / low, when known

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        v = v.lower()
        if v not in ("allow", "deny"):
            raise ValueError("action must be allow or deny")
        return v

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, v: str) -> str:
        return v.upper()


class GuidanceCitation(BaseModel):
    id: str
    title: str
    source: str
    snippet: str


class Finding(BaseModel):
    rule_id: str
    risk: str  # risky / safe
    severity: str  # high / medium / low
    summary: str
    proposed_fix: str
    citations: list[GuidanceCitation] = []
    status: str = "pending_review"  # pending_review | approved | rejected
    approved: bool = False


class AuditReport(BaseModel):
    trace_id: str
    rule_id: str
    rule: FirewallRule
    finding: Finding
    llm_used: bool = False
    llm_mode: str = "offline"  # offline | live
    run_path: str = ""
