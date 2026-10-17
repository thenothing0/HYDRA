"""Tests for the AdvancedReportEngine."""

import json
from pathlib import Path

import pytest

from hydra.reporting import AdvancedReportEngine


FINDINGS = [
    {"name": "reentrancy", "severity": "critical", "type": "rce",
     "matched_at": "Vault.sol:10", "description": "External call before state update",
     "remediation": "Use checks-effects-interactions", "confidence": 0.7},
    {"name": "weak_hash", "severity": "medium",
     "matched_at": "app.py:7", "description": "MD5 used", "evidence": "hashlib.md5("},
    {"name": "info_leak", "severity": "info", "matched_at": "x.py:1"},
]


class TestAdvancedReportEngine:
    def test_generates_all_formats(self, tmp_path):
        engine = AdvancedReportEngine(output_dir=str(tmp_path))
        saved = engine.generate(target="example.com", scan_id="s1", findings=FINDINGS)
        assert set(saved) == {"markdown", "json", "html"}
        for path in saved.values():
            assert Path(path).exists()

    def test_severity_ordering_and_breakdown(self, tmp_path):
        engine = AdvancedReportEngine(output_dir=str(tmp_path))
        saved = engine.generate(target="example.com", scan_id="s2", findings=FINDINGS)
        data = json.loads(Path(saved["json"]).read_text(encoding="utf-8"))
        # Critical must sort before medium before info
        sevs = [f["severity"] for f in data["findings"]]
        assert sevs == ["critical", "medium", "info"]
        bd = data["meta"]["severity_breakdown"]
        assert bd["critical"] == 1 and bd["medium"] == 1 and bd["info"] == 1

    def test_markdown_includes_remediation_and_evidence(self, tmp_path):
        engine = AdvancedReportEngine(output_dir=str(tmp_path))
        saved = engine.generate(target="example.com", scan_id="s3", findings=FINDINGS)
        md = Path(saved["markdown"]).read_text(encoding="utf-8")
        assert "checks-effects-interactions" in md   # remediation
        assert "hashlib.md5" in md                    # evidence
        assert "Vault.sol:10" in md                   # location

    def test_empty_findings_still_produces_report(self, tmp_path):
        engine = AdvancedReportEngine(output_dir=str(tmp_path))
        saved = engine.generate(target="example.com", scan_id="s4", findings=[])
        data = json.loads(Path(saved["json"]).read_text(encoding="utf-8"))
        assert data["meta"]["total_findings"] == 0

    def test_cvss_assigned_by_severity(self, tmp_path):
        engine = AdvancedReportEngine(output_dir=str(tmp_path))
        saved = engine.generate(target="example.com", scan_id="s5", findings=FINDINGS)
        data = json.loads(Path(saved["json"]).read_text(encoding="utf-8"))
        crit = next(f for f in data["findings"] if f["severity"] == "critical")
        assert crit["cvss_score"] >= 9.0
