"""CLI: python -m firewall_audit_agent.cli --rule-id RULE-002 [--approve]"""
from __future__ import annotations

import argparse
import json

from .agent import run_audit
from .embeddings_store import GuidanceStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit one firewall rule.")
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--approve", action="store_true", help="Human approval for the proposed fix.")
    parser.add_argument("--ingest", action="store_true", help="Ingest guidance docs into Chroma first.")
    args = parser.parse_args()
    if args.ingest:
        store = GuidanceStore()
        print(f"Ingested {store.ingest()} guidance docs into Chroma.")
    report = run_audit(args.rule_id, approve=args.approve)
    print(json.dumps(report.model_dump(), indent=2))


if __name__ == "__main__":
    main()
