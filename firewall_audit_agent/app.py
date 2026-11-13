"""FastAPI app: POST /audit, GET /health, GET /metrics.
Structured JSON logs, trace IDs, run history saved to files by the agent.
"""
from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent import run_audit
from .logging_utils import get_logger
from .rules import load_rules

logger = get_logger(__name__)
app = FastAPI(title="firewall-audit-agent", version="0.1.0")
_started = time.time()
_counters = {"audits": 0, "approved": 0, "pending_review": 0}


class AuditRequest(BaseModel):
    rule_id: str
    approve: bool = False


@app.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": round(time.time() - _started, 1)}


@app.get("/metrics")
def metrics():
    return {"audits_total": _counters["audits"], "approved_total": _counters["approved"],
            "pending_review_total": _counters["pending_review"], "uptime_seconds": round(time.time() - _started, 1)}


@app.get("/rules")
def rules():
    return [{"id": r.id, "source": r.source, "dest": r.dest, "port": r.port,
             "protocol": r.protocol, "action": r.action, "description": r.description,
             "label": r.label, "severity": r.severity} for r in load_rules()]


@app.post("/audit")
def audit(request: AuditRequest):
    trace_id = uuid.uuid4().hex[:16]
    logger.info(f"audit rule_id={request.rule_id} approve={request.approve}", extra={"trace_id": trace_id})
    try:
        report = run_audit(request.rule_id, approve=request.approve)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    _counters["audits"] += 1
    if report.finding.approved:
        _counters["approved"] += 1
    else:
        _counters["pending_review"] += 1
    return report.model_dump()
