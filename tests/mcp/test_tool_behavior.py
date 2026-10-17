"""
MCP Tool-Behavior Harness (Pillar 4) — mitigates Risk #2.

Drives each MCP tool end-to-end through the REAL _run() subprocess pipeline
against the deterministic fake binaries on PATH (see conftest `fake_tools`).
Verifies that each tool resolves its binary, executes, and parses output into
the documented JSON shape. No _run monkeypatching → genuine coverage of the
boundary, offline.
"""

import json


import mcp_server
from tests._doubles import FAKE_TOOLS


def test_subfinder_parses_subdomains():
    res = json.loads(mcp_server.subfinder_scan("example.com"))
    assert res["count"] == 3
    assert "api.example.com" in res["subdomains"]


def test_amass_parses_subdomains():
    res = json.loads(mcp_server.amass_enum("example.com"))
    assert res["count"] == 3


def test_httpx_probe_runs_and_returns_output():
    res = json.loads(mcp_server.httpx_probe("example.com"))
    assert res["success"] is True
    assert "api.example.com" in res["output"]


def test_nuclei_parses_jsonl_findings():
    res = json.loads(mcp_server.nuclei_scan("https://example.com"))
    assert res["count"] == 2
    sevs = {f["severity"] for f in res["findings"]}
    assert "medium" in sevs and "info" in sevs


def test_nuclei_scan_list_parses_findings():
    res = json.loads(mcp_server.nuclei_scan_list("a.example.com\nb.example.com"))
    assert res["count"] == 2


def test_katana_parses_endpoints():
    res = json.loads(mcp_server.katana_crawl("https://example.com"))
    assert res["count"] == 3
    assert any("login" in u for u in res["endpoints"])


def test_gau_parses_urls():
    res = json.loads(mcp_server.gau_urls("example.com"))
    assert res["count"] == 3


def test_whatweb_detects_tech():
    res = json.loads(mcp_server.whatweb_detect("https://example.com"))
    assert res["success"] is True
    assert "nginx" in res["output"]


def test_wafw00f_detects_waf():
    res = json.loads(mcp_server.wafw00f_detect("https://example.com"))
    assert "Cloudflare" in res["output"]


def test_nmap_reports_ports():
    res = json.loads(mcp_server.nmap_scan("example.com"))
    assert "80/tcp" in res["output"]


def test_dnsx_resolves():
    res = json.loads(mcp_server.dnsx_resolve("example.com", record_type="A"))
    assert "93.184.216.34" in res["output"]


def test_sqlmap_runs():
    res = json.loads(mcp_server.sqlmap_scan("https://example.com/item?id=1"))
    assert "injection" in res["output"].lower()


def test_gxss_runs():
    res = json.loads(mcp_server.gxss_check("https://example.com/?q=1"))
    assert res["success"] is True


def test_dalfox_runs():
    res = json.loads(mcp_server.dalfox_scan("https://example.com/?q=1"))
    assert res["success"] is True


def test_ffuf_runs_with_wordlist(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n")
    res = json.loads(mcp_server.ffuf_fuzz("https://example.com/FUZZ", wordlist=str(wl)))
    assert res["success"] is True
    assert "admin" in res["output"]


def test_full_recon_pipeline():
    res = json.loads(mcp_server.full_recon("example.com"))
    assert res["subdomain_count"] == 3
    assert res["live_count"] >= 1
    assert "nginx" in res["technologies"]


def test_check_tools_finds_all_fakes():
    res = json.loads(mcp_server.check_tools())
    # Optional real tools without an execution double need not be installed.
    assert set(FAKE_TOOLS) <= set(res["tools"])
    assert all(res["tools"][name]["available"] for name in FAKE_TOOLS)
    assert res["available"] == sum(tool["available"] for tool in res["tools"].values())


def test_check_tools_counts_missing_optional_tools(monkeypatch):
    monkeypatch.setattr(mcp_server.shutil, "which", lambda name: f"/fixtures/{name}" if name in FAKE_TOOLS else None)
    res = json.loads(mcp_server.check_tools())
    assert res["available"] == len(FAKE_TOOLS)
    assert res["total"] == len(res["tools"])
    assert res["total"] > res["available"]
    assert not res["tools"]["hashcat"]["available"]
