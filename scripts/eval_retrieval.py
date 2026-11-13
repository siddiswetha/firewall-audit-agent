"""Retrieval eval: real embeddings vs keyword-overlap baseline.

Queries are labelled with the guidance doc(s) that answer them.
Writes evals/retrieval_eval.json with recall@3 and recall@5 for both
methods, from an actual run.
Usage: python scripts/eval_retrieval.py [--persist-dir PATH]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

QUERIES = [
    ("Is allowing SSH from the internet risky?", ["G02-open-admin-ports", "G03-broad-source"]),
    ("Should I open remote desktop to everyone?", ["G02-open-admin-ports", "G03-broad-source"]),
    ("Is a rule that allows any source to any destination safe?", ["G04-any-any", "G01-least-privilege"]),
    ("Can a database be reached from the internet on port 5432?", ["G10-database-ports", "G02-open-admin-ports"]),
    ("What is the least privilege principle for firewall rules?", ["G01-least-privilege", "G07-default-deny"]),
    ("Should outbound traffic be controlled as well as inbound?", ["G05-egress", "G06-logging-monitoring"]),
    ("Why log firewall rules and monitor denied connections?", ["G06-logging-monitoring", "G05-egress"]),
    ("What does default deny mean?", ["G07-default-deny", "G01-least-privilege"]),
    ("How should a network be segmented?", ["G08-segmentation", "G13-zero-trust"]),
    ("How often should firewall rules be reviewed and when do they expire?", ["G09-change-management", "G12-review-and-expiry"]),
    ("Is MySQL port 3306 safe to expose publicly?", ["G10-database-ports", "G03-broad-source"]),
    ("What is zero trust for internal network traffic?", ["G13-zero-trust", "G08-segmentation"]),
]


def recall_at_k(retrieved_ids: list[str], relevant: list[str], k: int) -> float:
    top = retrieved_ids[:k]
    if not relevant:
        return 0.0
    return len(set(top) & set(relevant)) / len(relevant)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--persist-dir", default=None)
    args = parser.parse_args()

    from firewall_audit_agent.embeddings_store import GuidanceStore, keyword_search, load_guidance_docs

    docs = load_guidance_docs()
    store = GuidanceStore(persist_dir=args.persist_dir)
    store.ingest(docs)

    emb_r3, emb_r5, kw_r3, kw_r5 = [], [], [], []
    per_query = []
    for query, relevant in QUERIES:
        emb_ids = [c.id for c in store.retrieve(query, k=5)]
        kw_ids = [d["id"] for d in keyword_search(query, docs, k=5)]
        r = {
            "query": query,
            "relevant": relevant,
            "embedding_retrieved": emb_ids,
            "keyword_retrieved": kw_ids,
            "embedding_recall@3": recall_at_k(emb_ids, relevant, 3),
            "embedding_recall@5": recall_at_k(emb_ids, relevant, 5),
            "keyword_recall@3": recall_at_k(kw_ids, relevant, 3),
            "keyword_recall@5": recall_at_k(kw_ids, relevant, 5),
        }
        per_query.append(r)
        emb_r3.append(r["embedding_recall@3"]); emb_r5.append(r["embedding_recall@5"])
        kw_r3.append(r["keyword_recall@3"]); kw_r5.append(r["keyword_recall@5"])

    def mean(xs: list[float]) -> float:
        return round(sum(xs) / len(xs), 4) if xs else 0.0

    result = {
        "n_queries": len(QUERIES),
        "embedding_recall@3": mean(emb_r3),
        "embedding_recall@5": mean(emb_r5),
        "keyword_recall@3": mean(kw_r3),
        "keyword_recall@5": mean(kw_r5),
        "per_query": per_query,
    }
    out = ROOT / "evals" / "retrieval_eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "per_query"}, indent=2))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
