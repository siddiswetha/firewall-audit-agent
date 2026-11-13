"""Train the LoRA rule-risk classifier and evaluate base vs fine-tuned
on the SAME held-out set.

Base model: google/bert_uncased_L-2_H-128_A-2 (2 layers, 128 hidden, ~4M params),
frozen, with its untrained classification head — plus a majority-class
baseline, both stated in the output. Fine-tuned: PEFT LoRA (r=8,
alpha=16, dropout 0.1, target q/k/v), 3 epochs, batch 8, lr 5e-4,
CPU, seed 42. Writes models/lora-risk/ and evals/lora_eval.json.
Usage: python scripts/train_lora.py
"""
from __future__ import annotations

import json
import os
import random
from pathlib import Path

import torch
from torch.utils.data import DataLoader, Dataset

ROOT = Path(__file__).resolve().parents[1]
BASE_MODEL = os.environ.get("LORA_BASE_MODEL", "google/bert_uncased_L-2_H-128_A-2")
LABELS = ["risky", "safe"]
EPOCHS = int(os.environ.get("LORA_EPOCHS", "3"))
BATCH = int(os.environ.get("LORA_BATCH", "8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TextDataset(Dataset):
    def __init__(self, examples, tokenizer):
        self.examples = examples
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        ex = self.examples[idx]
        enc = self.tokenizer(ex["text"], truncation=True, max_length=128)
        return {"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"],
                "label": LABELS.index(ex["label"])}


def collate(batch, tokenizer):
    maxlen = max(len(b["input_ids"]) for b in batch)
    input_ids, masks, labels = [], [], []
    for b in batch:
        pad = maxlen - len(b["input_ids"])
        input_ids.append(b["input_ids"] + [tokenizer.pad_token_id] * pad)
        masks.append(b["attention_mask"] + [0] * pad)
        labels.append(b["label"])
    return {
        "input_ids": torch.tensor(input_ids),
        "attention_mask": torch.tensor(masks),
        "labels": torch.tensor(labels),
    }


def metrics(preds: list[int], gold: list[int]) -> dict:
    n = len(gold)
    correct = sum(p == g for p, g in zip(preds, gold))
    acc = correct / n if n else 0.0
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
    # Macro F1
    out["macro_f1"] = round((out["risky_f1"] + out["safe_f1"]) / 2, 4)
    return out


@torch.no_grad()
def evaluate(model, loader, device) -> list[int]:
    model.eval()
    preds = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        logits = model(input_ids=batch["input_ids"], attention_mask=batch["attention_mask"]).logits
        preds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
    return preds


def main() -> None:
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    torch.manual_seed(42)
    random.seed(42)
    device = torch.device("cpu")
    torch.set_num_threads(4)

    train = load_jsonl(ROOT / "data" / "lora_train.jsonl")
    test = load_jsonl(ROOT / "data" / "lora_test.jsonl")
    gold = [LABELS.index(e["label"]) for e in test]
    majority = max(set(gold), key=gold.count)
    majority_preds = [majority] * len(gold)
    majority_metrics = metrics(majority_preds, gold)
    print("majority baseline:", majority_metrics)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token or "[PAD]"
    base = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
    test_loader = DataLoader(TextDataset(test, tokenizer), batch_size=BATCH,
                             collate_fn=lambda b: collate(b, tokenizer))
    base_preds = evaluate(base, test_loader, device)
    base_metrics = metrics(base_preds, gold)
    print("base (untrained head):", base_metrics)

    config = LoraConfig(r=8, lora_alpha=16, lora_dropout=0.1, bias="none",
                        task_type="SEQ_CLS", target_modules=["query", "key", "value"])
    model = get_peft_model(base, config)
    model.print_trainable_parameters()
    train_loader = DataLoader(TextDataset(train, tokenizer), batch_size=BATCH, shuffle=True,
                              collate_fn=lambda b: collate(b, tokenizer))
    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-4)
    model.train()
    for epoch in range(EPOCHS):
        total_loss = 0.0
        for batch in train_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            out = model(input_ids=batch["input_ids"], attention_mask=batch["attention_mask"], labels=batch["labels"])
            out.loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            total_loss += float(out.loss)
        print(f"epoch {epoch+1}/{EPOCHS} mean loss {total_loss/len(train_loader):.4f}", flush=True)

    tuned_preds = evaluate(model, test_loader, device)
    tuned_metrics = metrics(tuned_preds, gold)
    print("fine-tuned LoRA:", tuned_metrics)

    out_dir = ROOT / "models" / "lora-risk"
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))

    result = {
        "base_model": BASE_MODEL,
        "task": "binary rule-risk classification: risky vs safe",
        "train_n": len(train), "test_n": len(test),
        "epochs": EPOCHS, "batch_size": BATCH, "lora_r": 8, "lora_alpha": 16,
        "majority_baseline": majority_metrics,
        "base_untrained_head": base_metrics,
        "lora_fine_tuned": tuned_metrics,
    }
    out = ROOT / "evals" / "lora_eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out} and {out_dir}")


if __name__ == "__main__":
    main()
