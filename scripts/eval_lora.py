"""Evaluate the saved LoRA adapter on the held-out set, recomputing
the headline numbers from the saved model (not from a stored file).
Usage: python scripts/eval_lora.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

LABELS = ["risky", "safe"]


def metrics(preds, gold):
    n = len(gold)
    acc = sum(p == g for p, g in zip(preds, gold)) / n if n else 0.0
    out = {"accuracy": round(acc, 4), "n": n}
    for i, name in enumerate(LABELS):
        tp = sum(p == i and g == i for p, g in zip(preds, gold))
        fp = sum(p == i and g != i for p, g in zip(preds, gold))
        fn = sum(p != i and g == i for p, g in zip(preds, gold))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[f"{name}_precision"] = round(prec, 4)
        out[f"{name}_recall"] = round(rec, 4)
        out[f"{name}_f1"] = round(f1, 4)
    out["macro_f1"] = round((out["risky_f1"] + out["safe_f1"]) / 2, 4)
    return out


def main() -> None:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    model_dir = ROOT / "models" / "lora-risk"
    if not (model_dir / "adapter_config.json").exists():
        print("No saved LoRA adapter found — run scripts/train_lora.py first.")
        return
    base_name = "google/bert_uncased_L-2_H-128_A-2"
    tokenizer = AutoTokenizer.from_pretrained(base_name)
    base = AutoModelForSequenceClassification.from_pretrained(base_name, num_labels=2)
    model = PeftModel.from_pretrained(base, str(model_dir))
    model.eval()
    test = [json.loads(line) for line in (ROOT / "data" / "lora_test.jsonl").read_text().splitlines() if line.strip()]
    gold = [LABELS.index(e["label"]) for e in test]
    preds = []
    with torch.no_grad():
        for ex in test:
            inputs = tokenizer(ex["text"], return_tensors="pt", truncation=True, max_length=128)
            logits = model(**inputs).logits
            preds.append(int(torch.argmax(logits, dim=-1)))
    result = metrics(preds, gold)
    print(json.dumps(result, indent=2))
    stored = json.loads((ROOT / "evals" / "lora_eval.json").read_text())
    print("stored lora_fine_tuned:", json.dumps(stored["lora_fine_tuned"], indent=2))
    assert result == stored["lora_fine_tuned"], "recomputed metrics differ from evals/lora_eval.json"
    print("Recomputed metrics match evals/lora_eval.json.")


if __name__ == "__main__":
    main()
