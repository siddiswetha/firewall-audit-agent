"""Ingest guidance docs into Chroma. Usage: python scripts/ingest.py"""
from __future__ import annotations

from firewall_audit_agent.embeddings_store import GuidanceStore


def main() -> None:
    store = GuidanceStore()
    print(f"Ingested {store.ingest()} guidance docs into Chroma.")


if __name__ == "__main__":
    main()
