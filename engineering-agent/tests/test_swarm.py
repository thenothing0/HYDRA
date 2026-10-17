"""
╔══════════════════════════════════════════════════════════════╗
║  Swarm tests — offline, network-free                         ║
╚══════════════════════════════════════════════════════════════╝

Covers the Path-C swarm wiring:
  - node._scope_gate      fail-closed at the node boundary
  - node._resolve_role    role resolution (--role beats env; unknown → all)
  - node._build_bus       in-memory vs Redis bus selection
  - registry.build_agents the five pipeline agents, in phase order
  - SwarmOrchestrator.run_scan  end-to-end over an in-memory bus with a
                          tool-name-routing fake MCP
  - never-exploit invariant  the swarm issues only benign tool calls; no
                          recorded param is an exploitation payload

No Redis, no real tools, no live traffic. Mirrors test_hunt.py / test_confirm.py.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest

from hydra.hunt.safety import is_exploitation_payload
from hydra.memory.bus import MemoryBus
from hydra.swarm import node
from hydra.swarm.base_agent import BaseAgent
from hydra.swarm.orchestrator import SwarmOrchestrator
from hydra.swarm.registry import build_agents, PIPELINE_AGENT_TYPES


def _run(coro):
    return asyncio.run(coro)

# ── Fakes ────────────────────────────────────────────────────

class _Scope:
    """Minimal scope engine: .is_loaded + .validate_target()."""
    def __init__(self, loaded=True, allow_host=""):
        self.is_loaded = loaded
        self._allow_host = allow_host

    def validate_target(self, host):
        ok = (not self._allow_host) or (self._allow_host in host)
        return SimpleNamespace(allowed=ok, reason="" if ok else "oos")


# Nuclei JSONL a routing MCP returns for "nuclei_scan": one real-shaped finding
# carrying evidence (matched-at) so it survives validation-first filtering.
_NUCLEI_JSONL = json.dumps({
    "template-id": "CVE-2021-1234",
    "info": {"name": "Example Exposure", "severity": "high",
             "description": "demo finding"},
    "host": "https://sub.target.tld",
    "matched-at": "https://sub.target.tld/status",
    "type": "http",
})


class RoutingMCP:
    """Fake MCP: benign per-tool output, records every call."""
    def __init__(self):
        self.calls = []

    async def execute_tool(self, tool_name, params, timeout=None):
        self.calls.append((tool_name, dict(params)))
        return {"success": True, "output": self._route(tool_name),
                "tool_used": tool_name, "return_code": 0}

    @staticmethod
    def _route(tool_name):
        return {
            "subdomain_enum": "sub.target.tld\n",
            "http_probe": "https://sub.target.tld\n",
            "endpoint_discovery": "https://sub.target.tld/api\n"
                                  "https://sub.target.tld/login\n",
            "nuclei_scan": _NUCLEI_JSONL,
            "tech_detect": "nginx\nPHP\n",
        }.get(tool_name, "")


def _iter_param_strings(params):
    """Yield every string value in an MCP params dict (recursing lists)."""
    for v in params.values():
        if isinstance(v, str):
            yield v
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str):
                    yield item

# ── node._scope_gate — fail-closed ───────────────────────────

def test_scope_gate_no_scope_refused():
    ok, reason = node._scope_gate(_Scope(loaded=False), "target.tld", False)
    assert ok is False
    assert "fail-closed" in reason


def test_scope_gate_none_engine_refused():
    ok, _ = node._scope_gate(None, "target.tld", False)
    assert ok is False


def test_scope_gate_allow_no_scope():
    ok, reason = node._scope_gate(_Scope(loaded=False), "target.tld", True)
    assert ok is True
    assert "allow-no-scope" in reason


def test_scope_gate_loaded_in_scope():
    ok, reason = node._scope_gate(
        _Scope(loaded=True, allow_host="target.tld"), "app.target.tld", False)
    assert ok is True
    assert reason == "in scope"


def test_scope_gate_loaded_out_of_scope():
    ok, reason = node._scope_gate(
        _Scope(loaded=True, allow_host="target.tld"), "evil.example.com", False)
    assert ok is False
    assert "out of scope" in reason


# ── node._resolve_role ───────────────────────────────────────

@pytest.mark.parametrize("role", ["coordinator", "worker", "all"])
def test_resolve_role_explicit(monkeypatch, role):
    monkeypatch.setattr(node, "get_config",
                        lambda: SimpleNamespace(node_role=""))
    assert node._resolve_role(SimpleNamespace(role=role)) == role


def test_resolve_role_from_env(monkeypatch):
    monkeypatch.setattr(node, "get_config",
                        lambda: SimpleNamespace(node_role="worker"))
    assert node._resolve_role(SimpleNamespace(role="")) == "worker"


def test_resolve_role_flag_beats_env(monkeypatch):
    monkeypatch.setattr(node, "get_config",
                        lambda: SimpleNamespace(node_role="coordinator"))
    assert node._resolve_role(SimpleNamespace(role="worker")) == "worker"

def test_resolve_role_unknown_defaults_all(monkeypatch):
    monkeypatch.setattr(node, "get_config",
                        lambda: SimpleNamespace(node_role="bogus"))
    assert node._resolve_role(SimpleNamespace(role="")) == "all"


def test_resolve_role_case_insensitive(monkeypatch):
    monkeypatch.setattr(node, "get_config",
                        lambda: SimpleNamespace(node_role=""))
    assert node._resolve_role(
        SimpleNamespace(role="COORDINATOR")) == "coordinator"


# ── node._build_bus — in-memory vs Redis ─────────────────────

def _cfg(distributed=False, queue_mode="local", url="redis://cache:6379/0"):
    return SimpleNamespace(
        distributed=distributed,
        queue=SimpleNamespace(mode=queue_mode),
        redis=SimpleNamespace(url=url, host="cache", port=6379),
    )


def test_build_bus_in_memory(monkeypatch):
    monkeypatch.setattr(node, "get_config", lambda: _cfg())
    bus = node._build_bus()
    assert isinstance(bus, MemoryBus)
    assert bus._redis_url is None


def test_build_bus_redis_via_distributed(monkeypatch):
    monkeypatch.setattr(node, "get_config", lambda: _cfg(distributed=True))
    assert node._build_bus()._redis_url == "redis://cache:6379/0"


def test_build_bus_redis_via_queue_mode(monkeypatch):
    monkeypatch.setattr(node, "get_config",
                        lambda: _cfg(queue_mode="distributed"))
    assert node._build_bus()._redis_url == "redis://cache:6379/0"


# ── registry.build_agents — the five pipeline agents ─────────

def test_build_agents_pipeline():
    agents = build_agents(PIPELINE_AGENT_TYPES, MemoryBus())
    assert [a.AGENT_TYPE for a in agents] == list(PIPELINE_AGENT_TYPES)
    assert all(isinstance(a, BaseAgent) for a in agents)
    assert set(PIPELINE_AGENT_TYPES) == {
        "recon", "vuln_research", "exploit_hypothesis",
        "validation", "reporting",
    }

# ── end-to-end SwarmOrchestrator.run_scan ────────────────────

def test_run_scan_end_to_end(monkeypatch, tmp_path):
    # Keep the reporting agent's report.json/report.md writes inside tmp_path.
    monkeypatch.setattr("hydra.swarm.reporting_agent.REPORTS_DIR", tmp_path)

    mcp = RoutingMCP()
    orch = SwarmOrchestrator(mcp_client=mcp, scope_engine=None, timeout=30)
    result = _run(orch.run_scan("target.tld", {}))

    assert result["status"] == "completed"
    # The Nuclei finding survives to the flattened findings list.
    assert result["findings"], "expected at least one finding"
    assert any(f.get("template_id") == "CVE-2021-1234"
               for f in result["findings"] if isinstance(f, dict))
    # The scan actually drove tools end to end (not a no-op).
    assert any(name == "nuclei_scan" for name, _ in mcp.calls)


# ── never-exploit invariant ──────────────────────────────────

_BENIGN_TOOLS = {
    "subdomain_enum", "http_probe", "endpoint_discovery",
    "nuclei_scan", "tech_detect",
}


def test_swarm_issues_only_benign_calls(monkeypatch, tmp_path):
    monkeypatch.setattr("hydra.swarm.reporting_agent.REPORTS_DIR", tmp_path)

    mcp = RoutingMCP()
    orch = SwarmOrchestrator(mcp_client=mcp, scope_engine=None, timeout=30)
    _run(orch.run_scan("target.tld", {}))

    assert mcp.calls, "swarm made no tool calls"
    for tool_name, params in mcp.calls:
        assert tool_name in _BENIGN_TOOLS, f"unexpected tool: {tool_name}"
        for value in _iter_param_strings(params):
            assert is_exploitation_payload(value) is False, (
                f"exploitation payload issued via {tool_name}: {value!r}")
