"""Tests for the PyTorch ML models (FP classifier + vuln classifier)."""

import pytest

from hydra.ml import FalsePositiveClassifier, VulnerabilityClassifier, torch_available
from hydra.ml.features import encode_finding, FEATURE_DIM

torch = pytest.importorskip("torch") if torch_available() else None
requires_torch = pytest.mark.skipif(not torch_available(), reason="PyTorch not installed")


class TestFeatures:
    def test_fixed_length(self):
        v = encode_finding({"severity": "high", "type": "sqli",
                            "tool_used": "nuclei", "confidence": 0.9})
        assert len(v) == FEATURE_DIM

    def test_handles_missing_fields(self):
        v = encode_finding({})
        assert len(v) == FEATURE_DIM
        assert all(isinstance(x, float) for x in v)

    def test_severity_onehot(self):
        crit = encode_finding({"severity": "critical"})
        info = encode_finding({"severity": "info"})
        assert crit != info


def _synthetic_fp_samples():
    """High-confidence critical/high findings = TP; low-confidence info = FP."""
    samples = []
    for i in range(15):
        samples.append(({"name": "SQLi", "type": "sqli", "severity": "critical",
                         "confidence": 0.9, "tool_used": "nuclei",
                         "evidence": "err"}, 1))
        samples.append(({"name": "banner", "type": "info", "severity": "info",
                         "confidence": 0.15, "tool_used": "whatweb"}, 0))
    return samples


@requires_torch
class TestFalsePositiveClassifier:
    def test_trains_and_predicts(self, tmp_path):
        clf = FalsePositiveClassifier(model_path=str(tmp_path / "fp.pt"))
        result = clf.train(_synthetic_fp_samples())
        assert result["trained"] is True
        assert result["train_accuracy"] >= 0.8

        tp = clf.predict({"name": "SQLi", "type": "sqli", "severity": "critical",
                          "confidence": 0.92, "tool_used": "nuclei", "evidence": "x"})
        fp = clf.predict({"name": "banner", "type": "info", "severity": "info",
                          "confidence": 0.1, "tool_used": "whatweb"})
        assert tp.source == "model"
        assert tp.probability > fp.probability

    def test_insufficient_data_reports_not_trained(self, tmp_path):
        clf = FalsePositiveClassifier(model_path=str(tmp_path / "fp.pt"))
        result = clf.train([({"severity": "high", "confidence": 0.8}, 1)] * 3)
        assert result["trained"] is False
        assert result["reason"] == "insufficient samples"

    def test_predict_without_model_uses_heuristic(self, tmp_path):
        clf = FalsePositiveClassifier(model_path=str(tmp_path / "missing.pt"))
        pred = clf.predict({"severity": "critical", "confidence": 0.9})
        assert pred.source == "heuristic"
        assert 0.0 <= pred.probability <= 1.0

    def test_filter_findings_annotates(self, tmp_path):
        clf = FalsePositiveClassifier(model_path=str(tmp_path / "fp.pt"))
        clf.train(_synthetic_fp_samples())
        findings = [
            {"name": "SQLi", "type": "sqli", "severity": "critical",
             "confidence": 0.9, "tool_used": "nuclei", "evidence": "x"},
            {"name": "banner", "type": "info", "severity": "info",
             "confidence": 0.1, "tool_used": "whatweb"},
        ]
        kept = clf.filter_findings(findings, threshold=0.5)
        assert all("fp_probability" in f for f in findings)
        assert len(kept) <= len(findings)


def _synthetic_vuln_samples():
    data = [
        ("Reflected XSS", "Cross-site scripting in search param", "xss"),
        ("Stored XSS", "Script injection persisted in profile", "xss"),
        ("Blind SQLi", "SQL injection in login", "sqli"),
        ("Union SQLi", "SQL injection error based", "sqli"),
        ("SSRF", "Server-side request forgery to metadata", "ssrf"),
        ("SSRF via webhook", "Internal request forgery", "ssrf"),
    ]
    return [({"name": n, "description": d}, lbl) for n, d, lbl in data] * 2


@requires_torch
class TestVulnerabilityClassifier:
    def test_trains_and_classifies(self, tmp_path):
        clf = VulnerabilityClassifier(model_path=str(tmp_path / "vuln.pt"))
        result = clf.train(_synthetic_vuln_samples())
        assert result["trained"] is True
        pred = clf.predict({"name": "Reflected XSS",
                            "description": "cross-site scripting in query"})
        assert pred.source == "model"
        assert pred.label in result["classes"]

    def test_similarity_returned(self, tmp_path):
        clf = VulnerabilityClassifier(model_path=str(tmp_path / "vuln.pt"))
        clf.train(_synthetic_vuln_samples())
        pred = clf.predict({"name": "SQL injection", "description": "sqli in id param"},
                           top_k_similar=3)
        assert isinstance(pred.similar, list)
        assert len(pred.similar) >= 1
        assert "similarity" in pred.similar[0]

    def test_keyword_fallback_without_model(self, tmp_path):
        clf = VulnerabilityClassifier(model_path=str(tmp_path / "none.pt"))
        pred = clf.predict({"name": "SQL injection", "description": "sqli"})
        assert pred.source == "keyword"
        assert pred.label == "sqli"
