"""Security contracts for the live process component, independent of installed tools."""
import subprocess
from types import SimpleNamespace

import pytest

import mcp_server
from hydra.mcp.process_boundary import execute_tool


def finalize(binary, cmd, result, elapsed=0):
    return result


def test_missing_binary_never_executes(monkeypatch):
    from hydra.mcp import process_boundary as boundary
    monkeypatch.setattr(boundary.shutil, "which", lambda name: None)
    monkeypatch.setattr(boundary.subprocess, "run", lambda *a, **kw: pytest.fail("Missing binary spawned"))
    result = execute_tool(["missing-fixture"], finalize=finalize)
    assert not result["success"]
    assert "not installed" in result["error"]


@pytest.mark.parametrize("return_code,success", [(0, True), (2, False)])
def test_argv_and_input_are_forwarded_without_shell(monkeypatch, return_code, success):
    from hydra.mcp import process_boundary as boundary
    monkeypatch.setattr(boundary.shutil, "which", lambda name: "/fixture/tool")
    seen = {}
    def run(cmd, **kwargs):
        seen.update(cmd=cmd, **kwargs)
        return SimpleNamespace(returncode=return_code, stdout="done", stderr="diagnostic")
    monkeypatch.setattr(boundary.subprocess, "run", run)
    result = execute_tool(["fixture", "argument with spaces"], timeout=3, stdin_data="input", finalize=finalize)
    assert seen["cmd"] == ["fixture", "argument with spaces"]
    assert not seen.get("shell", False)
    assert seen["input"] == "input" and seen["timeout"] == 3
    assert result["success"] is success


def test_output_and_stderr_are_bounded(monkeypatch):
    from hydra.mcp import process_boundary as boundary
    monkeypatch.setattr(boundary.shutil, "which", lambda name: "/fixture/tool")
    monkeypatch.setattr(boundary.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="x" * 40, stderr="y" * 60000))
    result = execute_tool(["fixture"], finalize=finalize, max_output_chars=10)
    assert result["truncated"] and result["output"].startswith("x" * 10)
    assert len(result["stderr"]) == 50000


@pytest.mark.parametrize("partial", [None, b"partial", "x" * 40])
def test_timeout_preserves_bounded_partial_evidence(monkeypatch, partial):
    from hydra.mcp import process_boundary as boundary
    monkeypatch.setattr(boundary.shutil, "which", lambda name: "/fixture/tool")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1, output=partial)
    monkeypatch.setattr(boundary.subprocess, "run", timeout)
    result = execute_tool(["fixture"], finalize=finalize, max_output_chars=10)
    assert result["timed_out"]
    assert result["success"] is bool(partial)
    assert result["truncated"] is (partial is not None and len(partial) > 10)


def test_execution_error_is_reported_and_finalized(monkeypatch):
    from hydra.mcp import process_boundary as boundary
    monkeypatch.setattr(boundary.shutil, "which", lambda name: "/fixture/tool")
    def fail(*args, **kwargs):
        raise OSError("fixture execution error")
    monkeypatch.setattr(boundary.subprocess, "run", fail)
    recorded = []
    def record(binary, cmd, result, elapsed=0):
        recorded.append((binary, result))
        return result
    result = execute_tool(["fixture"], finalize=record)
    assert result["success"] is False
    assert len(recorded) == 1 and recorded[0][0] == "fixture"


def test_facade_preserves_proxy_and_telemetry_overrides(monkeypatch):
    monkeypatch.setattr(mcp_server.shutil, "which", lambda name: "/fixture/tool")
    monkeypatch.setattr(mcp_server, "USE_TOR", True)
    monkeypatch.setattr(mcp_server, "PROXYCHAINS_BIN", "/fixture/proxychains")
    captured = []
    monkeypatch.setattr(mcp_server.subprocess, "run", lambda cmd, **kw: captured.append(cmd) or SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    assert mcp_server._run(["fixture", "argument"])["success"]
    assert captured == [["/fixture/proxychains", "-q", "fixture", "argument"]]
