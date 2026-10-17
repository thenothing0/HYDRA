"""
Vulnerability Classifier — a PyTorch MLP head over sentence embeddings.

Takes a finding's text (name + description), embeds it with the shared
EmbeddingEngine (all-MiniLM-L6-v2, 384-dim), and classifies the vulnerability
type. Also offers nearest-neighbor similarity against the training set so
callers can surface "similar known vulnerabilities".

Degrades gracefully to a keyword classifier if torch or a trained model is
unavailable.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hydra.config import get_config
from hydra.memory.semantic import EmbeddingEngine

logger = logging.getLogger("hydra.ml.vuln")

# Keyword fallback map: label → indicative substrings
_KEYWORDS = {
    "xss": ["xss", "cross-site script", "script injection"],
    "sqli": ["sql injection", "sqli", "sql error"],
    "ssrf": ["ssrf", "server-side request", "internal request"],
    "idor": ["idor", "insecure direct object", "object reference"],
    "rce": ["rce", "remote code", "command execution", "code injection"],
    "lfi": ["lfi", "local file", "path traversal", "directory traversal"],
    "ssti": ["ssti", "template injection"],
    "reentrancy": ["reentrancy", "reentrant"],
    "auth-bypass": ["auth bypass", "authentication bypass", "broken auth"],
    "info": ["information disclosure", "info leak", "version disclosure"],
}


def _keyword_label(text: str) -> Tuple[str, float]:
    t = (text or "").lower()
    for label, kws in _KEYWORDS.items():
        if any(k in t for k in kws):
            return label, 0.55
    return "unknown", 0.3


@dataclass
class VulnPrediction:
    label: str
    probability: float
    source: str                                   # "model" | "keyword"
    similar: List[Dict[str, Any]] = field(default_factory=list)


class VulnerabilityClassifier:
    """Embedding → MLP classifier with kNN similarity."""

    def __init__(self, model_path: Optional[str] = None):
        self.cfg = get_config().ml
        base = model_path or os.path.join(self.cfg.model_dir, "vuln_classifier.pt")
        self.model_path = Path(base)
        self.meta_path = self.model_path.with_suffix(".meta.json")
        self._embedder = EmbeddingEngine(get_config().semantic_memory.embedding_model)
        self._model = None
        self._labels: List[str] = []
        self._train_embeddings = None    # torch tensor for kNN
        self._train_labels: List[str] = []
        self._loaded = False

    @staticmethod
    def _text(finding: Dict[str, Any]) -> str:
        return " ".join(str(finding.get(k, "")) for k in ("name", "description", "type")).strip()

    def _build_model(self, n_classes: int):
        import torch.nn as nn

        class _Head(nn.Module):
            def __init__(self, in_dim, hidden, out_dim):
                super().__init__()
                self.net = nn.Sequential(
                    nn.Linear(in_dim, hidden), nn.ReLU(), nn.Dropout(0.1),
                    nn.Linear(hidden, out_dim),
                )

            def forward(self, x):
                return self.net(x)

        return _Head(self.cfg.vuln_embedding_dim, self.cfg.vuln_hidden_dim, n_classes)

    # ── Training ───────────────────────────────
    def train(self, samples: List[Tuple[Dict[str, Any], str]]) -> Dict[str, Any]:
        """Train on (finding, label) pairs where label is a vuln-type string."""
        try:
            import torch
            import torch.nn as nn
        except Exception:
            return {"trained": False, "reason": "torch not available"}

        clean = [(self._text(f), str(lbl)) for f, lbl in samples if self._text(f) and lbl]
        labels = sorted({lbl for _, lbl in clean})
        if len(clean) < max(6, len(labels) * 2) or len(labels) < 2:
            return {"trained": False, "reason": "insufficient samples",
                    "have": len(clean), "classes": len(labels)}

        torch.manual_seed(self.cfg.seed)
        embs = self._embedder.embed([t for t, _ in clean])
        X = torch.tensor(embs, dtype=torch.float32)
        label_idx = {l: i for i, l in enumerate(labels)}
        y = torch.tensor([label_idx[l] for _, l in clean], dtype=torch.long)

        model = self._build_model(len(labels))
        opt = torch.optim.Adam(model.parameters(), lr=self.cfg.vuln_lr)
        loss_fn = nn.CrossEntropyLoss()

        model.train()
        last_loss = 0.0
        for _ in range(self.cfg.vuln_epochs):
            opt.zero_grad()
            loss = loss_fn(model(X), y)
            loss.backward()
            opt.step()
            last_loss = float(loss.item())

        model.eval()
        with torch.no_grad():
            acc = float((model(X).argmax(dim=1) == y).float().mean().item())

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({"state_dict": model.state_dict(),
                    "labels": labels,
                    "train_embeddings": X,
                    "train_labels": [l for _, l in clean]}, self.model_path)
        self.meta_path.write_text(json.dumps({"labels": labels, "samples": len(clean)}),
                                  encoding="utf-8")
        self._model = model
        self._labels = labels
        self._train_embeddings = X
        self._train_labels = [l for _, l in clean]
        self._loaded = True
        logger.info(f"🧠 Vuln classifier trained: {len(clean)} samples, "
                    f"{len(labels)} classes (acc={acc:.2%})")
        return {"trained": True, "samples": len(clean), "classes": labels,
                "train_accuracy": round(acc, 4), "final_loss": round(last_loss, 4)}

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
            self._labels = blob["labels"]
            model = self._build_model(len(self._labels))
            model.load_state_dict(blob["state_dict"])
            model.eval()
            self._model = model
            self._train_embeddings = blob.get("train_embeddings")
            self._train_labels = blob.get("train_labels", [])
            return True
        except Exception as e:
            logger.warning(f"Vuln model load failed: {e}")
            return False

    def predict(self, finding: Dict[str, Any], top_k_similar: int = 3) -> VulnPrediction:
        text = self._text(finding)
        if not self._ensure_loaded():
            label, prob = _keyword_label(text)
            return VulnPrediction(label=label, probability=prob, source="keyword")
        try:
            import torch
            emb = torch.tensor([self._embedder.embed_single(text)], dtype=torch.float32)
            with torch.no_grad():
                probs = torch.softmax(self._model(emb), dim=1)[0]
                idx = int(probs.argmax().item())
            similar = self._nearest(emb, top_k_similar)
            return VulnPrediction(label=self._labels[idx],
                                  probability=round(float(probs[idx].item()), 4),
                                  source="model", similar=similar)
        except Exception as e:
            logger.debug(f"Vuln predict fell back to keyword: {e}")
            label, prob = _keyword_label(text)
            return VulnPrediction(label=label, probability=prob, source="keyword")

    def _nearest(self, emb, k: int) -> List[Dict[str, Any]]:
        if self._train_embeddings is None or not self._train_labels:
            return []
        try:
            import torch
            sims = torch.nn.functional.cosine_similarity(emb, self._train_embeddings)
            k = min(k, sims.shape[0])
            top = torch.topk(sims, k)
            return [{"label": self._train_labels[int(i)],
                     "similarity": round(float(s), 4)}
                    for s, i in zip(top.values, top.indices)]
        except Exception:
            return []
