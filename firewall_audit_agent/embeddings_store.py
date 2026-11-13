"""ChromaDB vector store with real embeddings.

Production default: Chroma's default ONNX MiniLM embedding
(all-MiniLM-L6-v2) — no torch needed for retrieval.
Tests may inject a small deterministic embedding function so they
run fast without downloading a model.
"""
from __future__ import annotations

import re
from pathlib import Path

import chromadb

from .models import GuidanceCitation

STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "for", "on", "in", "is",
    "it", "as", "with", "by", "from", "that", "this", "should", "be",
}


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOPWORDS}


def keyword_search(query: str, docs: list[dict], k: int = 3) -> list[dict]:
    """Keyword-overlap baseline, used ONLY for the retrieval eval —
    never as the agent's retriever."""
    qt = _tokens(query)
    scored = sorted(docs, key=lambda d: len(qt & _tokens(d["text"])), reverse=True)
    return [d for d in scored if len(qt & _tokens(d["text"])) > 0][:k]


def load_guidance_docs(guidance_dir: str | Path | None = None) -> list[dict]:
    guidance_dir = Path(guidance_dir) if guidance_dir else Path(__file__).resolve().parents[1] / "data" / "guidance"
    docs = []
    for path in sorted(guidance_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        title = lines[0].lstrip("# ").strip() if lines else path.stem
        body = " ".join(lines[1:])
        docs.append({"id": path.stem, "title": title, "text": body, "source": path.name})
    return docs


class GuidanceStore:
    def __init__(self, persist_dir: str | Path | None = None, embedding_function=None):
        persist_dir = Path(persist_dir) if persist_dir else Path(__file__).resolve().parents[1] / "chroma_db"
        self.client = chromadb.PersistentClient(path=str(persist_dir))
        kwargs: dict = {"name": "guidance"}
        if embedding_function is not None:
            kwargs["embedding_function"] = embedding_function
        self.collection = self.client.get_or_create_collection(**kwargs)

    def ingest(self, docs: list[dict] | None = None) -> int:
        docs = docs if docs is not None else load_guidance_docs()
        if self.collection.count() == len(docs):
            return self.collection.count()
        # Re-ingest cleanly if the count differs (e.g. docs changed).
        try:
            self.client.delete_collection("guidance")
        except Exception:
            pass
        self.collection = self.client.get_or_create_collection(name="guidance")
        self.collection.add(
            ids=[d["id"] for d in docs],
            documents=[f"{d['title']}. {d['text']}" for d in docs],
            metadatas=[{"title": d["title"], "source": d["source"]} for d in docs],
        )
        return self.collection.count()

    def retrieve(self, query: str, k: int = 3) -> list[GuidanceCitation]:
        results = self.collection.query(query_texts=[query], n_results=k)
        citations: list[GuidanceCitation] = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        ids = results.get("ids", [[]])[0]
        for doc_id, doc, meta in zip(ids, docs, metas):
            citations.append(GuidanceCitation(
                id=doc_id,
                title=(meta or {}).get("title", doc_id),
                source=(meta or {}).get("source", ""),
                snippet=doc[:280],
            ))
        return citations
