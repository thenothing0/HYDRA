"""Regression checks for startup, policy enforcement and process cleanup."""
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import TestClient, TestServer

from hydra.main import HydraEngine
from hydra.mcp.http_server import MCPHTTPServer
from hydra.mcp.tool_server import MCPToolServer
from hydra.mcp.tool_server import TOOL_REGISTRY
from hydra.scope import ScopePolicyEngine

ROOT = Path(__file__).resolve().parents[1]


def test_installed_dirsearch_accepts_command_options():
    binary = Path(sys.executable).parent / ("dirsearch.exe" if os.name == "nt" else "dirsearch")
    if not binary.exists():
        pytest.skip("optional dirsearch tool not installed")
    cmd = TOOL_REGISTRY["dirsearch"]["build_cmd"]({"target": "http://example.com"})
    # --help exits during parsing: no target request is made.
    result = subprocess.run([str(binary), *cmd[1:], "--help"], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_default_wordlist_is_available():
    from hydra.config import WORDLISTS_DIR
    assert len((WORDLISTS_DIR / "common.txt").read_text().splitlines()) >= 10


def scope(**extra):
    engine = ScopePolicyEngine()
    engine.load_from_dict({"program": "local-test", "in_scope": ["example.com"], **extra})
    return engine


def test_loaded_empty_scope_denies_targets():
    assert not scope(in_scope=[]).validate_target("example.com").allowed


@pytest.mark.parametrize("logical,params", [
    ("port_scan", {"target": "example.com"}),
    ("http_probe", {"target": "example.com", "tool": "nmap"}),
])
def test_policy_checks_resolved_binary(logical, params):
    server = MCPToolServer()
    server._available_tools = {"nmap": True}
    server.set_scope_engine(scope(forbidden_testing=["port scanning"]))
    result = asyncio.run(server.execute_tool(logical, params))
    assert result.get("blocked_by_scope")


def test_stdin_scope_is_checked_before_execution():
    server = MCPToolServer()
    server._available_tools = {"httpx": True}
    server.set_scope_engine(scope())
    result = asyncio.run(server.execute_tool("http_probe", {
        "target": "example.com", "_stdin": "example.com\nevil.test",
    }))
    assert result.get("blocked_by_scope")


def test_engine_attaches_scope_to_tool_layer(tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"in_scope": ["example.com"]}))
    engine = HydraEngine("example.com", scope_file=str(scope_path), output_dir=str(tmp_path))
    asyncio.run(engine.init())
    assert engine.tool_server._scope_engine is engine._scope


@pytest.mark.parametrize("target", ["..", "../..", "..\\..", "C:\\tmp\\source"])
def test_output_directory_cannot_escape_root(tmp_path, target):
    engine = HydraEngine(target, output_dir=str(tmp_path))
    assert engine.output_dir.resolve().is_relative_to(tmp_path.resolve())
    assert engine.output_dir.resolve() != tmp_path.resolve()


def test_cli_refusal_has_clear_error_and_nonzero_exit(tmp_path):
    result = subprocess.run([
        sys.executable, "-m", "hydra.main", "-t", "example.com",
        "--output-dir", str(tmp_path),
    ], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "No authorized scope loaded" in result.stdout


def test_missing_local_target_is_an_error(tmp_path):
    engine = HydraEngine(str(tmp_path / "missing"), workflow="code_review")
    assert asyncio.run(engine.run())["error"] == "invalid_target"


def test_all_tools_missing_is_not_reported_as_success(tmp_path):
    engine = HydraEngine("example.com", allow_no_scope=True,
                         output_dir=str(tmp_path), no_ai=True, learn=False)
    async def run():
        await engine.init()
        engine.tool_server._available_tools = {}
        return await engine.run()
    result = asyncio.run(run())
    assert result["error"] == "tool_execution_failed"
    assert result["status"] == "failed"
    assert result["tool_failures"]


def test_no_ai_skips_model_features(tmp_path, monkeypatch):
    target = tmp_path / "safe.py"
    target.write_text("print('hello')\n")
    engine = HydraEngine(str(target), workflow="code_review", output_dir=str(tmp_path / "out"),
                         no_ai=True, ml_filter=True, learn=False)
    enrichment = AsyncMock()
    monkeypatch.setattr(engine, "_enrich_from_memory", enrichment)
    monkeypatch.setattr(engine, "_apply_ml", lambda: pytest.fail("ML ran with --no-ai"))
    async def run():
        await engine.init()
        return await engine.run()
    assert asyncio.run(run())["status"] == "completed"
    enrichment.assert_not_called()


def test_timeout_kills_and_reaps_process(monkeypatch):
    class Process:
        returncode = None
        killed = False
        drained = False

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def communicate(self, input=None):
            if not self.killed:
                await asyncio.Event().wait()
            self.drained = True
            return b"", b""

    proc = Process()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    server = MCPToolServer()
    server._available_tools = {"subfinder": True}
    params = {"target": "example.com", "tool": "subfinder"}
    result = asyncio.run(server.execute_tool("subdomain_enum", params, timeout=0.01))
    assert not result["success"]
    assert proc.killed and proc.drained
    assert params["tool"] == "subfinder"


def test_python_httpx_is_not_mistaken_for_security_scanner(monkeypatch):
    import hydra.mcp.tool_server as tool_module
    monkeypatch.setattr(tool_module.shutil, "which", lambda name: "httpx.exe" if name == "httpx" else None)
    proc = type("Process", (), {"returncode": 2,
                               "communicate": AsyncMock(return_value=(b"", b"No such option: -version"))})()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
    server = MCPToolServer()
    asyncio.run(server.initialize())
    assert not server.get_available_tools()["httpx"]


def test_tool_concurrency_limit_is_enforced(monkeypatch):
    active = 0
    peak = 0
    class Process:
        returncode = 0
        async def communicate(self, input=None):
            nonlocal active
            await asyncio.sleep(0.01)
            active -= 1
            return b"ok", b""
    async def spawn(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        return Process()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    server = MCPToolServer()
    server._available_tools = {"subfinder": True}
    server._semaphore = asyncio.Semaphore(1)
    async def run():
        return await asyncio.gather(*(server.execute_tool("subfinder", {"target": "example.com"})
                                      for _ in range(3)))
    assert all(r["success"] for r in asyncio.run(run()))
    assert peak == 1


@pytest.mark.asyncio
async def test_http_default_scope_gate_and_request_validation():
    tools = MCPToolServer()
    tools.execute_tool = AsyncMock()
    server = MCPHTTPServer(tools)
    async with TestClient(TestServer(server.app)) as client:
        response = await client.get("/health")
        assert response.status == 200
        for payload in [[], {"tool": "nmap", "params": []},
                        {"tool": "nmap", "timeout": -1}, {"tool": 5},
                        {"tool": "nmap", "params": {"target": 123}},
                        {"tool": "nmap", "params": {"targets": "example.com"}}]:
            response = await client.post("/execute", json=payload)
            assert response.status == 400
        response = await client.post("/execute", json={
            "tool": "nmap", "params": {"target": "example.com"},
        })
        assert response.status == 403
        tools.execute_tool.assert_not_called()


def test_dotenv_loads_before_config_defaults(tmp_path):
    # Load a standalone copy so the real .env and singleton remain untouched.
    project = tmp_path / "isolated"
    package = project / "hydra"
    package.mkdir(parents=True)
    config = package / "config.py"
    config.write_text((ROOT / "hydra/config.py").read_text(encoding="utf-8"), encoding="utf-8")
    (project / ".env").write_text("MCP_PORT=17891\n")
    command = "import runpy,sys; c=runpy.run_path(sys.argv[1]); print(c['get_config']().mcp.port)"
    env = dict(os.environ)
    env.pop("MCP_PORT", None)
    first = subprocess.check_output([sys.executable, "-c", command, str(config)], env=env, text=True)
    assert first.strip() == "17891"
    env["MCP_PORT"] = "17892"
    second = subprocess.check_output([sys.executable, "-c", command, str(config)], env=env, text=True)
    assert second.strip() == "17892"


def test_stdio_mcp_initialization_and_scope_refusal():
    pytest.importorskip("mcp.server.fastmcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    env = {**os.environ, "HYDRA_ALLOW_NO_SCOPE": "0", "HYDRA_ENFORCE_SCOPE": "true",
           "HYDRA_SCOPE_FILE": "", "HYDRA_SCOPE_URL": "", "PYTHONIOENCODING": "utf-8"}
    async def run():
        params = StdioServerParameters(command=sys.executable,
                                       args=[str(ROOT / "mcp_server.py")], env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                registered = await session.list_tools()
                assert "subfinder_scan" in {t.name for t in registered.tools}
                result = await session.call_tool("subfinder_scan", {"domain": "example.com"})
                payload = json.loads(result.content[0].text)
                assert payload.get("blocked_by_scope") or "scope" in payload.get("error", "").lower()
    asyncio.run(asyncio.wait_for(run(), timeout=30))
