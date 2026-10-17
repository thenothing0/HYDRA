"""
False-Positive Classifier — a small PyTorch MLP that predicts whether a
finding is a true positive, trained on the labelled rows the LearningEngine
records via `mark_true_positive`.

Degrades gracefully:
  • no torch installed        → heuristic fallback (confidence-based)
  • too few labelled samples  → heuristic fallback
  • model file missing        → heuristic fallback until trained
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hydra.config import get_config
from hydra.ml.features import encode_finding, FEATURE_DIM

logger = logging.getLogger("hydra.ml.fp")


@dataclass
class FPPrediction:
    """Prediction for a single finding."""
    is_true_positive: bool
    probability: float          # P(true positive), 0..1
    source: str                 # "model" | "heuristic"


def _heuristic(finding: Dict[str, Any]) -> FPPrediction:
    """Confidence/severity heuristic used when the model isn't available."""
    try:
        conf = float(finding.get("confidence", finding.get("confidence_score", 0.5)))
    except (TypeError, ValueError):
        conf = 0.5
    sev = str(finding.get("severity", "info")).lower()
    sev_boost = {"critical": 0.15, "high": 0.1, "medium": 0.0,
                 "low": -0.05, "info": -0.1}.get(sev, 0.0)
    prob = max(0.0, min(1.0, conf + sev_boost))
    return FPPrediction(is_true_positive=prob >= 0.5, probability=round(prob, 4),
                        source="heuristic")


class FalsePositiveClassifier:
    """Trainable FP filter with a PyTorch MLP backend."""

    def __init__(self, model_path: Optional[str] = None):
        self.cfg = get_config().ml
        self.model_path = Path(model_path or os.path.join(self.cfg.model_dir, "fp_classifier.pt"))
        self._model = None
        self._loaded = False

    # ── Model definition ───────────────────────
    def _build_model(self):
        import torch.nn as nn

        class _MLP(nn.Module):
            def __init__(self, in_dim: int, hidden: int):
                super().__init__()
                self.net = nn.Sequential(
                    nn.Linear(in_dim, hidden), nn.ReLU(),
                    nn.Linear(hidden, hidden // 2), nn.ReLU(),
                    nn.Linear(hidden // 2, 1),
                )

            def forward(self, x):
                return self.net(x)

        return _MLP(FEATURE_DIM, self.cfg.fp_hidden_dim)

    # ── Training ───────────────────────────────
    def train(self, samples: List[Tuple[Dict[str, Any], int]]) -> Dict[str, Any]:
        """Train on (finding, label) pairs. label: 1=true positive, 0=false.

        Returns a summary dict; raises nothing on insufficient data — it just
        reports `trained: False`.
        """
        try:
            import torch
            import torch.nn as nn
        except Exception:
            return {"trained": False, "reason": "torch not available"}

        labelled = [(f, int(y)) for f, y in samples if y in (0, 1)]
        if len(labelled) < self.cfg.fp_min_samples:
            return {"trained": False, "reason": "insufficient samples",
                    "have": len(labelled), "need": self.cfg.fp_min_samples}
        if len({y for _, y in labelled}) < 2:
            return {"trained": False, "reason": "only one class present"}

        torch.manual_seed(self.cfg.seed)
        X = torch.tensor([encode_finding(f) for f, _ in labelled], dtype=torch.float32)
        y = torch.tensor([[float(l)] for _, l in labelled], dtype=torch.float32)

        model = self._build_model()
        opt = torch.optim.Adam(model.parameters(), lr=self.cfg.fp_lr)
        loss_fn = nn.BCEWithLogitsLoss()

        model.train()
        last_loss = 0.0
        for _ in range(self.cfg.fp_epochs):
            opt.zero_grad()
            logits = model(X)
            loss = loss_fn(logits, y)
            loss.backward()
            opt.step()
            last_loss = float(loss.item())

        # Training accuracy (sanity signal, not a held-out metric)
        model.eval()
        with torch.no_grad():
            preds = (torch.sigmoid(model(X)) >= 0.5).float()
            acc = float((preds == y).float().mean().item())

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({"state_dict": model.state_dict(),
                    "in_dim": FEATURE_DIM,
                    "hidden": self.cfg.fp_hidden_dim}, self.model_path)
        self._model = model
        self._loaded = True
        logger.info(f"🧠 FP classifier trained on {len(labelled)} samples "
                    f"(acc={acc:.2%}, loss={last_loss:.4f})")
        return {"trained": True, "samples": len(labelled),
                "train_accuracy": round(acc, 4), "final_loss": round(last_loss, 4),
                "model_path": str(self.model_path)}

    # ── Inference ──────────────────────────────
    def _ensure_loaded(self) -> bool:
        if self._loaded:
            return self._model is not None
        self._loaded = True
        try:
            import torch
        except Exception:
            return False
        if not self.model_path.exists():
            return False
        try:
            blob = torch.load(self.model_path, map_location="cpu", weights_only=False)
            model = self._build_model()
            model.load_state_dict(blob["state_dict"])
            model.eval()
            self._model = model
            return True
        except Exception as e:
            logger.warning(f"FP model load failed: {e}")
            return False

    def predict(self, finding: Dict[str, Any]) -> FPPrediction:
        """Predict whether one finding is a true positive."""
        if not self._ensure_loaded():
            return _heuristic(finding)
        try:
            import torch
            x = torch.tensor([encode_finding(finding)], dtype=torch.float32)
            with torch.no_grad():
                prob = float(torch.sigmoid(self._model(x)).item())
            return FPPrediction(is_true_positive=prob >= 0.5,
                                probability=round(prob, 4), source="model")
        except Exception as e:
            logger.debug(f"FP predict fell back to heuristic: {e}")
            return _heuristic(finding)

    def filter_findings(self, findings: List[Dict[str, Any]],
                        threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Return findings predicted to be true positives, annotated in place."""
        kept = []
        for f in findings:
            pred = self.predict(f)
            f["fp_probability"] = pred.probability
            f["fp_source"] = pred.source
            if pred.probability >= threshold:
                kept.append(f)
        return kept
