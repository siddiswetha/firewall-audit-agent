"""Rule-risk classifier.

Primary: a PEFT LoRA fine-tuned tiny transformer, loaded lazily so
the rest of the app works without torch. Falls back to the
deterministic heuristic in rules.py when no LoRA model is available.
"""
from __future__ import annotations

import os
from pathlib import Path

from .models import FirewallRule
from .rules import heuristic_risk

LABELS = ["risky", "safe"]


def describe_rule(rule: FirewallRule) -> str:
    return (
        f"{rule.action.capitalize()} {rule.protocol} port {rule.port} "
        f"from {rule.source} to {rule.dest}. {rule.description}"
    )


class RiskClassifier:
    def __init__(self, model_dir: str | Path | None = None):
        self.model_dir = Path(model_dir) if model_dir else Path(__file__).resolve().parents[1] / "models" / "lora-risk"
        self._model = None
        self._tokenizer = None
        self.available = False
        if (self.model_dir / "adapter_config.json").exists():
            try:
                self._load()
            except Exception:
                self.available = False

    def _load(self) -> None:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        base = os.environ.get("LORA_BASE_MODEL", "google/bert_uncased_L-2_H-128_A-2")
        self._tokenizer = AutoTokenizer.from_pretrained(base)
        base_model = AutoModelForSequenceClassification.from_pretrained(base, num_labels=2)
        self._model = PeftModel.from_pretrained(base_model, str(self.model_dir))
        self._model.eval()
        self._torch = torch
        self.available = True

    def predict(self, rule: FirewallRule) -> tuple[str, float]:
        """Return (label, confidence). Uses LoRA if loaded, else heuristic."""
        if self.available and self._model is not None:
            text = describe_rule(rule)
            inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
            with self._torch.no_grad():
                logits = self._model(**inputs).logits
                probs = self._torch.softmax(logits, dim=-1)[0]
            idx = int(probs.argmax())
            return LABELS[idx], float(probs[idx])
        risk, _severity = heuristic_risk(rule)
        return risk, 1.0
