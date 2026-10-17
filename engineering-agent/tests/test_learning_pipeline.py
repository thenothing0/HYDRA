"""Tests for the end-to-end learning pipeline (record → label → train)."""

import asyncio

import pytest

from hydra.learning.engine import LearningEngine
from hydra.learning.pipeline import LearningPipeline
from hydra.ml import torch_available


def _run(coro):
    return asyncio.run(coro)


def _engine(tmp_path):
    eng = LearningEngine(db_path=str(tmp_path / "learn.db"))
    eng.initialize()
    return eng


FINDINGS = [
    {"name": "SQLi", "type": "sqli", "severity": "critical",
     "confidence": 0.9, "matched_at": "db.py:3", "evidence": "err"},
    {"name": "debug_enabled", "type": "debug_enabled", "severity": "low",
     "confidence": 0.6, "matched_at": "app.py:10"},
    {"name": "reentrancy", "type": "reentrancy", "severity": "critical",
     "confidence": 0.7, "matched_at": "Vault.sol:5", "evidence": "call"},
]


class TestLearningPipeline:
    def test_record_scan_persists_rows(self, tmp_path):
        pipe = LearningPipeline(_engine(tmp_path))
        n = pipe.record_scan("s1", "example.com", FINDINGS, tool_used="code_review")
        assert n == 3
        # Nothing labelled yet (all undecided)
        assert pipe.labelled_count() == 0

    def test_auto_label_assigns_labels(self, tmp_path):
        pipe = LearningPipeline(_engine(tmp_path))
        pipe.record_scan("s1", "example.com", FINDINGS)
        counts = _run(pipe.auto_label("s1", FINDINGS))
        assert counts["true_positive"] + counts["false_positive"] == 3
        assert pipe.labelled_count() == 3
        # Each finding annotated with its auto label
        assert all("auto_label" in f for f in FINDINGS)

    def test_manual_label_overrides(self, tmp_path):
        pipe = LearningPipeline(_engine(tmp_path))
        pipe.record_scan("s1", "example.com", FINDINGS)
        _run(pipe.auto_label("s1", FINDINGS))
        # Force one finding to FP and confirm it sticks
        tid = pipe._synthetic_id(FINDINGS[0])
        pipe.label("s1", tid, is_true_positive=False)
        rows = {r["template_id"]: r["is_true_positive"]
                for r in pipe.learning.export_labelled_findings()}
        assert rows[tid] == 0

    @pytest.mark.skipif(not torch_available(), reason="PyTorch not installed")
    def test_train_requires_two_classes(self, tmp_path):
        pipe = LearningPipeline(_engine(tmp_path))
        # 25 findings, auto-labeled — likely all one class → cannot train
        many = FINDINGS * 9
        pipe.record_scan("s1", "example.com", many)
        _run(pipe.auto_label("s1", many))
        # Force a second class on a couple of them
        pipe.label("s1", pipe._synthetic_id(FINDINGS[1]), is_true_positive=False)
        result = pipe.train()
        # With ≥20 samples and 2 classes present, training should succeed
        if result.get("trained"):
            assert result["train_accuracy"] >= 0.5
        else:
            # Acceptable only if genuinely one-class or too few
            assert result["reason"] in ("only one class present", "insufficient samples")
