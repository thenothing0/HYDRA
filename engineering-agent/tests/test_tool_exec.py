"""Tests for the WIRED tool-execution path (offline — no real subprocess/network).

Covers the surfaces that actually run when HYDRA scans:
  * TOOL_REGISTRY build_cmd shapes (one per tool)
  * TOOL_ALIASES resolution + MCPToolServer.execute_tool decision logic
    (scope gate, unknown tool, unavailable tool, build failure, success/stats)
  * HydraEngine._parse_nuclei (nuclei JSONL → findings)
  * GitHubAdvisoriesAdapter parsing (public GHSA REST API)
  * build_parser CLI flag parsing

Every external effect is mocked: create_subprocess_exec and the adapters'
_get are stubbed, so this module never touches the network or the OS.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest

from hydra.mcp.tool_server import MCPToolServer, TOOL_REGISTRY, TOOL_ALIASES
from hydra.ingest.base import REGISTRY
from hydra.ingest.sources.github import GitHubAdvisoriesAdapter
from hydra.main import HydraEngine, build_parser


def _run(coro):
    return asyncio.run(coro)


# ── subprocess mock ────────────────────────────────
class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout, self._stderr, self.returncode = stdout, stderr, returncode

    async def communicate(self, input=None):
        return self._stdout, self._stderr


def _patch_exec(monkeypatch, capture, stdout=b"", stderr=b"", returncode=0):
    """Replace asyncio.create_subprocess_exec so execute_tool runs no real process."""
    async def fake_exec(*cmd, **kwargs):
        capture["cmd"] = list(cmd)
        capture["kwargs"] = kwargs
        return _FakeProc(stdout, stderr, returncode)
    monkeypatch.setattr(
        "hydra.mcp.tool_server.asyncio.create_subprocess_exec", fake_exec)


# ═══════════════════════════════════════════════════
#  TOOL_REGISTRY — build_cmd shapes
# ═══════════════════════════════════════════════════
class TestBuildCmd:
    def test_subfinder(self):
        assert TOOL_REGISTRY["subfinder"]["build_cmd"]({"target": "x.com"}) == \
            ["subfinder", "-d", "x.com", "-silent"]

    def test_amass_passive_vs_active(self):
        passive = TOOL_REGISTRY["amass"]["build_cmd"]({"target": "x", "mode": "passive"})
        assert passive == ["amass", "enum", "-passive", "-d", "x"]
        active = TOOL_REGISTRY["amass"]["build_cmd"]({"target": "x"})
        assert "-passive" not in active and active == ["amass", "enum", "-d", "x"]

    def test_httpx_stdin_vs_target(self):
        assert TOOL_REGISTRY["httpx"]["build_cmd"]({"_stdin": "a\nb"}) == \
            ["httpx", "-silent"]
        assert TOOL_REGISTRY["httpx"]["build_cmd"]({"target": "http://x"}) == \
            ["httpx", "-silent", "-u", "http://x"]

    def test_nuclei_default_and_tags(self):
        base = TOOL_REGISTRY["nuclei"]["build_cmd"]({"target": "http://x"})
        assert base[:4] == ["nuclei", "-u", "http://x", "-jsonl"]
        assert "-silent" in base and "medium,high,critical" in base
        assert "--tags" not in base
        tagged = TOOL_REGISTRY["nuclei"]["build_cmd"](
            {"target": "http://x", "tags": "cve,rce", "severity": "low"})
        assert "--tags" in tagged and "cve,rce" in tagged and "low" in tagged

    def test_ffuf_fuzz_suffix(self):
        cmd = TOOL_REGISTRY["ffuf"]["build_cmd"]({"target": "http://x"})
        assert "http://x/FUZZ" in cmd and cmd[0] == "ffuf" and "-s" in cmd

    def test_katana(self):
        assert TOOL_REGISTRY["katana"]["build_cmd"]({"target": "http://x"}) == \
            ["katana", "-u", "http://x", "-silent", "-d", "3"]

    def test_gau(self):
        assert TOOL_REGISTRY["gau"]["build_cmd"]({"target": "x.com"}) == ["gau", "x.com"]

    def test_whatweb(self):
        assert TOOL_REGISTRY["whatweb"]["build_cmd"]({"target": "x"}) == \
            ["whatweb", "x", "--color=never"]

    def test_wafw00f(self):
        assert TOOL_REGISTRY["wafw00f"]["build_cmd"]({"target": "x"}) == ["wafw00f", "x"]

    def test_nmap_default_and_ports(self):
        default = TOOL_REGISTRY["nmap"]["build_cmd"]({"target": "x"})
        assert default == ["nmap", "-sV", "--top-ports", "1000", "x"]
        custom = TOOL_REGISTRY["nmap"]["build_cmd"]({"target": "x", "ports": "80,443"})
        assert "80,443" in custom and "1000" not in custom

    def test_dirsearch(self):
        assert TOOL_REGISTRY["dirsearch"]["build_cmd"]({"target": "http://x"}) == \
            ["dirsearch", "-u", "http://x", "--output-formats=json", "-q"]

    def test_missing_target_raises(self):
        # build_cmd for a target-requiring tool must raise (not silently emit a
        # command with no target) — execute_tool relies on catching this.
        with pytest.raises(KeyError):
            TOOL_REGISTRY["subfinder"]["build_cmd"]({})


# ═══════════════════════════════════════════════════
#  TOOL_ALIASES — consistency
# ═══════════════════════════════════════════════════
class TestAliases:
    def test_every_alias_maps_to_registered_tool(self):
        for logical, physicals in TOOL_ALIASES.items():
            assert physicals, f"{logical} has no physical tools"
            for p in physicals:
                assert p in TOOL_REGISTRY, f"{logical} → unknown physical {p}"

    def test_known_logical_names(self):
        assert TOOL_ALIASES["subdomain_enum"] == ["subfinder", "amass"]
        assert TOOL_ALIASES["nuclei_scan"] == ["nuclei"]


# ═══════════════════════════════════════════════════
#  execute_tool — decision logic (mocked subprocess)
# ═══════════════════════════════════════════════════
class _Scope:
    """Minimal scope-engine stand-in."""
    def __init__(self, loaded=True, allowed=True, reason="", violations=None):
        self.is_loaded = loaded
        self._allowed, self._reason = allowed, reason
        self._violations = violations or []

    def validate_tool_execution(self, tool_name, target):
        return SimpleNamespace(allowed=self._allowed, reason=self._reason,
                               policy_violations=self._violations)


class TestExecuteTool:
    def test_resolves_alias_to_available_tool_and_runs(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": True, "amass": False}
        cap = {}
        _patch_exec(monkeypatch, cap, stdout=b"a.example.com\nb.example.com\n")
        res = _run(srv.execute_tool("subdomain_enum", {"target": "example.com"}))
        assert res["success"] is True
        assert res["tool_used"] == "subfinder"          # first available alias
        assert cap["cmd"] == ["subfinder", "-d", "example.com", "-silent"]
        assert "a.example.com" in res["output"]
        assert res["return_code"] == 0

    def test_skips_unavailable_first_alias(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": False, "amass": True}
        cap = {}
        _patch_exec(monkeypatch, cap, stdout=b"")
        res = _run(srv.execute_tool("subdomain_enum", {"target": "x", "mode": "passive"}))
        assert res["tool_used"] == "amass"
        assert cap["cmd"][:3] == ["amass", "enum", "-passive"]

    def test_explicit_tool_param_overrides_alias(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"nmap": True}
        cap = {}
        _patch_exec(monkeypatch, cap)
        res = _run(srv.execute_tool("anything", {"target": "x", "tool": "nmap"}))
        assert res["tool_used"] == "nmap" and cap["cmd"][0] == "nmap"

    def test_unknown_tool(self):
        srv = MCPToolServer()
        res = _run(srv.execute_tool("whatever", {"target": "x", "tool": "does_not_exist"}))
        assert res["success"] is False
        assert "Unknown tool" in res["error"]

    def test_unavailable_tool(self):
        srv = MCPToolServer()
        srv._available_tools = {}                         # nothing installed
        res = _run(srv.execute_tool("nuclei_scan", {"target": "http://x"}))
        assert res["success"] is False
        assert "not installed" in res["error"] and res["tool_used"] == "nuclei"

    def test_build_failure_is_caught(self):
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": True}
        # target key present-but-empty is falsy → scope gate skipped, but the
        # empty string still builds a (degenerate) command, so force a real
        # build error by removing target entirely via explicit tool.
        res = _run(srv.execute_tool("subdomain_enum", {"tool": "subfinder"}))
        assert res["success"] is False
        assert "Failed to build command" in res["error"]

    def test_scope_gate_blocks_out_of_scope(self):
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": True}
        srv.set_scope_engine(_Scope(loaded=True, allowed=False,
                                     reason="host not in program", violations=["oos"]))
        res = _run(srv.execute_tool("subdomain_enum", {"target": "evil.com"}))
        assert res["success"] is False
        assert res["blocked_by_scope"] is True
        assert "Scope violation" in res["error"]
        assert res["policy_violations"] == ["oos"]

    def test_scope_gate_allows_in_scope(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": True}
        srv.set_scope_engine(_Scope(loaded=True, allowed=True))
        cap = {}
        _patch_exec(monkeypatch, cap, stdout=b"in.scope.com\n")
        res = _run(srv.execute_tool("subdomain_enum", {"target": "in.scope.com"}))
        assert res["success"] is True and cap["cmd"][0] == "subfinder"

    def test_fail_open_when_no_scope_loaded(self, monkeypatch):
        # Documents CURRENT tool_server behaviour: with no scope engine the
        # in-process gate is fail-OPEN (the HTTP/root MCP layers add the
        # fail-closed gate). If this changes, this test should change too.
        srv = MCPToolServer()
        srv._available_tools = {"subfinder": True}
        cap = {}
        _patch_exec(monkeypatch, cap, stdout=b"x\n")
        res = _run(srv.execute_tool("subdomain_enum", {"target": "anything.com"}))
        assert res["success"] is True and "blocked_by_scope" not in res

    def test_stats_tracked_on_success(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"gau": True}
        _patch_exec(monkeypatch, {}, stdout=b"http://x/1\n")
        _run(srv.execute_tool("url_gather", {"target": "x"}))
        stats = srv.get_stats()
        assert stats["gau"]["total"] == 1 and stats["gau"]["success"] == 1

    def test_nonzero_return_code_is_failure(self, monkeypatch):
        srv = MCPToolServer()
        srv._available_tools = {"nmap": True}
        _patch_exec(monkeypatch, {}, stdout=b"", stderr=b"boom", returncode=1)
        res = _run(srv.execute_tool("port_scan", {"target": "x"}))
        assert res["success"] is False and res["return_code"] == 1
        assert res["stderr"] == "boom"


# ═══════════════════════════════════════════════════
#  HydraEngine._parse_nuclei
# ═══════════════════════════════════════════════════
class TestParseNuclei:
    def test_parses_jsonl(self):
        out = "\n".join([
            json.dumps({"info": {"name": "Reflected XSS", "severity": "high"},
                        "template-id": "xss-refl", "matched-at": "http://x/q",
                        "type": "http", "extracted-results": ["<script>"]}),
            json.dumps({"template-id": "tech-detect", "info": {},
                        "host": "http://x"}),
        ])
        f = HydraEngine._parse_nuclei(out)
        assert len(f) == 2
        assert f[0]["name"] == "Reflected XSS" and f[0]["severity"] == "high"
        assert f[0]["template_id"] == "xss-refl" and f[0]["matched_at"] == "http://x/q"
        assert f[0]["evidence"] == ["<script>"]
        # falls back: name→template-id, severity→info, matched_at→host
        assert f[1]["name"] == "tech-detect" and f[1]["severity"] == "info"
        assert f[1]["matched_at"] == "http://x"

    def test_nonjson_bracket_line_kept_raw(self):
        f = HydraEngine._parse_nuclei("[cve-2021-1] [high] http://x\nplain noise line")
        assert len(f) == 1                       # plain (no '[') skipped
        assert f[0]["raw"] is True and f[0]["severity"] == "info"

    def test_empty_and_blank(self):
        assert HydraEngine._parse_nuclei("") == []
        assert HydraEngine._parse_nuclei("   \n\n  ") == []


# ═══════════════════════════════════════════════════
#  GitHubAdvisoriesAdapter
# ═══════════════════════════════════════════════════
class TestGitHubAdapter:
    ADV = [
        {"summary": "SSRF in image proxy",
         "description": "server-side request forgery reaching metadata",
         "severity": "HIGH", "html_url": "https://github.com/advisories/GHSA-1",
         "ghsa_id": "GHSA-1", "published_at": "2025-01-01",
         "cwes": [{"name": "CWE-918 Server-Side Request Forgery"}]},
        {"summary": "", "description": "a sql injection in the id parameter",
         "severity": "unknown", "url": "https://x/2", "ghsa_id": "GHSA-2",
         "cwes": []},
    ]

    def test_registered(self):
        assert "github" in REGISTRY

    def test_parses_advisories(self):
        class _Mock(GitHubAdvisoriesAdapter):
            async def _get(self, url, headers=None, as_json=False):
                # First page returns the batch; any later page is empty.
                return TestGitHubAdapter.ADV if "page=1" in url else []

        ws = _run(_Mock().fetch(limit=10))
        assert len(ws) == 2
        # adv severity used directly when valid
        assert ws[0].severity == "high"
        assert ws[0].category == "ssrf"                 # from CWE name text
        assert ws[0].url == "https://github.com/advisories/GHSA-1"
        assert "GHSA-1" in ws[0].tags
        assert ws[0].published == "2025-01-01"
        # invalid severity → classify from text (no sev word) → medium fallback
        assert ws[1].severity == "medium"
        assert ws[1].category == "sqli"
        assert ws[1].title == "GHSA-2"                  # summary empty → ghsa_id
        assert ws[1].url == "https://x/2"               # falls back to url

    def test_empty_response_is_safe(self):
        class _Mock(GitHubAdvisoriesAdapter):
            async def _get(self, url, headers=None, as_json=False):
                return []
        assert _run(_Mock().fetch(limit=10)) == []

    def test_token_sets_auth_header(self):
        seen = {}

        class _Mock(GitHubAdvisoriesAdapter):
            async def _get(self, url, headers=None, as_json=False):
                seen["headers"] = headers
                return []
        _run(_Mock(token="ghp_secret").fetch(limit=1))
        assert seen["headers"].get("Authorization") == "Bearer ghp_secret"


# ═══════════════════════════════════════════════════
#  build_parser
# ═══════════════════════════════════════════════════
class TestBuildParser:
    def test_defaults(self):
        a = build_parser().parse_args(["-t", "example.com"])
        assert a.target == "example.com"
        assert a.workflow == "quick_recon"
        assert a.timeout == 120
        assert a.budget == 5.0
        assert a.ml_threshold == 0.5
        assert a.allow_no_scope is False
        assert a.no_ai is False

    def test_scope_flags(self):
        a = build_parser().parse_args(
            ["-t", "x", "--scope-file", "scope.json", "--allow-no-scope"])
        assert a.scope_file == "scope.json" and a.allow_no_scope is True

    def test_scope_url_and_token(self):
        a = build_parser().parse_args(
            ["--scope-url", "https://h1/prog", "--scope-token", "tok"])
        assert a.scope_url == "https://h1/prog" and a.scope_token == "tok"

    def test_invalid_workflow_rejected(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["-w", "not_a_real_workflow"])

    def test_ingest_flags(self):
        a = build_parser().parse_args(
            ["--ingest", "github,medium", "--ingest-limit", "5",
             "--ingest-query", "ssrf", "--ingest-no-train"])
        assert a.ingest == "github,medium" and a.ingest_limit == 5
        assert a.ingest_query == "ssrf" and a.ingest_no_train is True

    def test_label_takes_three_args(self):
        a = build_parser().parse_args(["--label", "scan1", "f1", "tp"])
        assert a.label == ["scan1", "f1", "tp"]

    def test_cve_intel_and_reindex(self):
        a = build_parser().parse_args(["--cve-intel", "CVE-2021-44228"])
        assert a.cve_intel == "CVE-2021-44228"
        assert build_parser().parse_args(["--reindex-corpus"]).reindex_corpus is True
