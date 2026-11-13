# firewall-audit-agent

A LangGraph agent that audits firewall / ACL rules against NIST and vendor
guidance, retrieved with real embeddings from ChromaDB. It proposes
least-privilege fixes only as **draft proposals** — nothing is presented
as approved or applied without explicit human approval.

This project was built from scratch to close four specific gaps:
no LangChain/LangGraph, no vector DB or embeddings (earlier RAG was
keyword-overlap), no production-style agentic deployment, and LoRA
fine-tuning that was mechanics-only with no measured gain.

All rules, guidance, and training data are synthetic and written for
this project. No real customer rules, no copied text. Guidance docs
paraphrase general firewall best practice (including concepts from
NIST SP 800-41) in original words.

## What it does

```
rule (data/rules.json)
  -> parse_rule
  -> retrieve_guidance   (LangGraph tool call into Chroma, top-3, with citations)
  -> classify_risk       (LoRA fine-tuned classifier, heuristic fallback)
  -> draft_finding       (live LLM if OPENAI_API_KEY is set, else labelled offline draft)
  -> human_review        (approval gate: approve=True only)
  -> final_report        (audit trail JSON saved to runs/<trace_id>.json)
```

- **60 synthetic firewall rules** in `data/rules.json` (26 risky / 34 safe),
  with source, destination, port, protocol, action, description, label, severity.
- **13 original guidance docs** in `data/guidance/` (least privilege,
  open admin ports 22/3389, broad sources, any-to-any, egress, logging,
  default deny, segmentation, change management, database ports, DNS,
  review/expiry, zero trust).
- **Human approval gate:** `approve=False` (the default) leaves the
  finding as `pending_review` with `approved: false`. Only an explicit
  `approve=True` marks it `approved`.

## How to run locally

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
# ML training deps only (optional, for LoRA training):
.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install -r requirements-ml.txt

python scripts/generate_data.py        # regenerates data/ (deterministic, seed 42)
PYTHONPATH=. python scripts/ingest.py  # ingest 13 guidance docs into Chroma

# CLI — one rule, offline draft by default
PYTHONPATH=. python -m firewall_audit_agent.cli --rule-id RULE-002
PYTHONPATH=. python -m firewall_audit_agent.cli --rule-id RULE-002 --approve

# API
PYTHONPATH=. uvicorn firewall_audit_agent.app:app --port 8000
curl localhost:8000/health
curl -X POST localhost:8000/audit -H 'Content-Type: application/json' \
  -d '{"rule_id": "RULE-002", "approve": false}'
```

Endpoints: `POST /audit`, `GET /health`, `GET /metrics`, `GET /rules`.
Structured JSON logs with a trace ID per request; run history is saved
to `runs/<trace_id>.json`.

### Docker

```bash
docker compose up --build
curl localhost:8000/health
```

## Using a real LLM

Set `OPENAI_API_KEY` (and optionally `OPENAI_BASE_URL` / `LLM_MODEL`,
default `gpt-4o-mini`). The client is OpenAI-compatible via httpx, so
Ollama works with `OPENAI_BASE_URL=http://localhost:11434/v1` and
`LLM_MODEL` set to a local model. The client is unit-tested against a
mocked HTTP endpoint.

Without a key, the agent uses a clearly labelled deterministic offline
explainer that drafts only from the retrieved guidance and the
classifier output. Offline output is **not** an LLM call, and the
report records `llm_mode: "offline"` and `llm_used: false`.

No live LLM run was performed while building this project — no API key
was available — so no live-LLM result is claimed anywhere.

## Reproduce the evals

```bash
PYTHONPATH=. python scripts/eval_retrieval.py   # -> evals/retrieval_eval.json
PYTHONPATH=. python scripts/train_lora.py        # -> models/lora-risk/, evals/lora_eval.json
PYTHONPATH=. python scripts/eval_lora.py         # recomputes LoRA numbers from the saved adapter
PYTHONPATH=. python -m pytest tests/ -q
```

## Results (measured, not claimed)

### Retrieval — embeddings vs keyword-overlap baseline (12 labelled queries)

| method | recall@3 | recall@5 |
| --- | --- | --- |
| Chroma + all-MiniLM-L6-v2 embeddings | 0.625 | 0.875 |
| Keyword-overlap baseline | 0.667 | 0.750 |

Embeddings win at recall@5 and are slightly behind at recall@3 on
these 12 queries — the queries are keyword-rich, so the baseline is
strong. Full per-query results: `evals/retrieval_eval.json`.

### LoRA rule-risk classifier — same 60 held-out examples for all rows

Base model: `google/bert_uncased_L-2_H-128_A-2` (2 layers, 128 hidden,
~4M params). LoRA r=8, alpha=16, dropout 0.1, 3 epochs, batch 8,
lr 5e-4, CPU. Train 240 / test 60, binary risky vs safe.
Trainable params: 12,546 / 4,398,724 (0.2852%).

| model | accuracy | macro F1 | risky P / R / F1 | safe P / R / F1 |
| --- | --- | --- | --- | --- |
| Majority baseline | 0.5000 | 0.3333 | 0.50 / 1.00 / 0.67 | 0.00 / 0.00 / 0.00 |
| Base, untrained head | 0.5833 | 0.5369 | 0.73 / 0.27 / 0.39 | 0.55 / 0.90 / 0.68 |
| LoRA fine-tuned | **0.9333** | **0.9330** | 0.88 / 1.00 / 0.94 | 1.00 / 0.87 / 0.93 |

Full numbers: `evals/lora_eval.json`. Re-running
`scripts/eval_lora.py` recomputes the fine-tuned row from the saved
adapter and asserts it matches the stored file.

### Tests

20 pytest tests pass (`tests/test_core.py`, `tests/test_agent_api.py`):
rule parsing, retrieval with citations, classifier fallback, human
gate (no approval = no approved proposal), LLM client against a
mocked HTTP endpoint, API `/health` and `/audit`, and checks that the
stored eval numbers are real and that fine-tuned accuracy beats the
base and majority baselines.

## Honest limitations

- All data is synthetic. Nothing here has audited a real firewall.
- Guidance is original paraphrase, not NIST text, and is a small
  sample (13 docs) — it does not cover every firewall scenario.
- The offline draft is not an LLM call. With no API key, findings are
  template drafts grounded in retrieved guidance only.
- The LoRA model is a tiny 2-layer BERT trained on 300 synthetic,
  template-generated examples. 0.933 accuracy on 60 held-out examples
  shows the pipeline works and the pattern is learnable; it does not
  prove the model would generalise to real rules.
- Retrieval is good at recall@5 (0.875) but not dominant at recall@3
  on this small query set (see table above).
- The FastAPI + Docker shape is production-style (health/metrics,
  structured logs, trace IDs, CI), not a deployed production service.
- The Chroma ONNX embedding model is downloaded from S3 on first use
  (~83 MB). If your network blocks that download, fetch it with curl
  into `~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/` first.
