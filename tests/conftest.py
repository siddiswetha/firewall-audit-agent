"""Pytest fixtures: deterministic hash embedding so Chroma tests run
fast without downloading the ONNX model."""
from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


class HashEmbeddingFunction:
    """Deterministic 384-dim embedding from a text hash. Test-only."""

    def __call__(self, input):
        vectors = []
        for text in input:
            seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
            rng = random.Random(seed)
            vectors.append([rng.uniform(-1, 1) for _ in range(384)])
        return vectors

    def name(self):
        return "hash-embedding-test-only"

    def is_legacy(self):
        return False


@pytest.fixture()
def guidance_store(tmp_path):
    from firewall_audit_agent.embeddings_store import GuidanceStore, load_guidance_docs

    store = GuidanceStore(persist_dir=tmp_path / "chroma", embedding_function=HashEmbeddingFunction())
    store.ingest(load_guidance_docs())
    return store
