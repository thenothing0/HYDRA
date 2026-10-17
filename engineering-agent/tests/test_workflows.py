"""Tests for the web3_audit and code_review CLI workflows."""

import asyncio
import json
from pathlib import Path

import pytest

from hydra.main import HydraEngine


VULN_PY = '''
import os, hashlib, random, subprocess
API_KEY = "sk-supersecret1234567890"

def run(cmd):
    subprocess.run(cmd, shell=True)
    eval(cmd)
    return hashlib.md5(b"x").hexdigest()

DEBUG = True
'''

CLEAN_PY = '''
def add(a, b):
    """Return the sum of two numbers."""
    return a + b
'''

VULN_SOL = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C {
    function f() public {
        (bool ok, ) = msg.sender.call{value: 1}("");
        require(ok);
    }
}
'''


def _run(coro):
    return asyncio.run(coro)


async def _make_engine(tmp_path, target, workflow):
    # code_review / web3_audit are LOCAL file-analysis workflows and are
    # exempt from network scope enforcement by design (no --allow-no-scope).
    engine = HydraEngine(target=str(target), workflow=workflow,
                         output_dir=str(tmp_path / "out"),
                         allow_no_scope=True)
    await engine.init()
    return engine


class TestCodeReviewWorkflow:
    def test_flags_vulnerable_python(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text(VULN_PY, encoding="utf-8")

        async def go():
            engine = await _make_engine(tmp_path, f, "code_review")
            await engine.run()
            return engine.findings

        findings = _run(go())
        names = {f["name"] for f in findings}
        assert "hardcoded_secret" in names
        assert "shell_injection" in names
        assert "dangerous_eval" in names
        assert "weak_hash" in names
        # Every finding must anchor to a file:line
        for finding in findings:
            assert ":" in finding["matched_at"]

    def test_clean_python_has_no_findings(self, tmp_path):
        f = tmp_path / "good.py"
        f.write_text(CLEAN_PY, encoding="utf-8")

        async def go():
            engine = await _make_engine(tmp_path, f, "code_review")
            await engine.run()
            return engine.findings

        assert _run(go()) == []

    def test_writes_report_files(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text(VULN_PY, encoding="utf-8")

        async def go():
            engine = await _make_engine(tmp_path, f, "code_review")
            return await engine.run()

        summary = _run(go())
        reports = summary.get("reports", {})
        assert "markdown" in reports and Path(reports["markdown"]).exists()
        assert "json" in reports and Path(reports["json"]).exists()
        md = Path(reports["markdown"]).read_text(encoding="utf-8")
        assert "HYDRA Security Assessment Report" in md


class TestWeb3AuditWorkflow:
    def test_audits_solidity_directory(self, tmp_path):
        (tmp_path / "C.sol").write_text(VULN_SOL, encoding="utf-8")

        async def go():
            engine = await _make_engine(tmp_path, tmp_path, "web3_audit")
            await engine.run()
            return engine.findings

        findings = _run(go())
        names = {f["name"] for f in findings}
        assert "reentrancy" in names

    def test_missing_path_is_handled(self, tmp_path):
        async def go():
            engine = await _make_engine(tmp_path, tmp_path / "nope.sol", "web3_audit")
            await engine.run()
            return engine.findings

        # Should not raise; simply produces no findings
        assert _run(go()) == []
