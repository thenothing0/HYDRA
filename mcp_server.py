#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA MCP Server — Security Tool Execution Layer           ║
║  Compatible with: Claude Code, Cursor, Cline, Windsurf      ║
║  Usage: Add to your AI coding agent's MCP config             ║
╚══════════════════════════════════════════════════════════════╝

This MCP server gives any AI coding agent direct access to
real security tools via the Model Context Protocol.

Project MCP config (register this file):
  - .mcp.json (Claude Code)
  - .cursor/mcp.json (Cursor)
  - cline_mcp_settings.json (Cline)
  - .claude/settings.json — enabledMcpjsonServers: ["hydra-security"]

Supported AI agents:
  - Claude Code:  auto-detected via .mcp.json
  - Cursor:       add to .cursor/mcp.json
  - Cline:        add to cline_mcp_settings.json
  - Windsurf:     add to ~/.windsurf/mcp.json
  - Any MCP-compatible client

All tools are REAL — executed via subprocess. No mocking.
"""

import json
import os
import re as _re
import shutil
import subprocess as subprocess  # Compatibility hook for process adapters/tests.
import sys
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP
from hydra.mcp.process_boundary import execute_tool as _execute_tool

# ──────────────────────────────────────────────
#  Server Setup
# ──────────────────────────────────────────────

mcp = FastMCP("hydra-security")


def _install_threaded_stdio_transport() -> None:
    """Use asyncio pipe reads when AnyIO stdin iteration stalls."""
    import asyncio
    from contextlib import asynccontextmanager

    import anyio
    import mcp.server.fastmcp.server as fastmcp_server
    from mcp import types as mcp_types
    from mcp.shared.message import SessionMessage

    @asynccontextmanager
    async def threaded_stdio_server():
        read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
        write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

        async def stdin_reader():
            try:
                async with read_stream_writer:
                    loop = asyncio.get_running_loop()
                    reader = asyncio.StreamReader()
                    protocol = asyncio.StreamReaderProtocol(reader)
                    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
                    while True:
                        line_bytes = await reader.readline()
                        if not line_bytes:
                            break
                        line = line_bytes.decode("utf-8")
                        try:
                            message = mcp_types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:  # pragma: no cover
                            await read_stream_writer.send(exc)
                            continue
                        await read_stream_writer.send(SessionMessage(message))
            except anyio.ClosedResourceError:  # pragma: no cover
                await anyio.lowlevel.checkpoint()

        async def stdout_writer():
            try:
                async with write_stream_reader:
                    async for session_message in write_stream_reader:
                        line = session_message.message.model_dump_json(by_alias=True, exclude_none=True) + "\n"
                        sys.stdout.write(line)
                        sys.stdout.flush()
            except anyio.ClosedResourceError:  # pragma: no cover
                await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            yield read_stream, write_stream

    fastmcp_server.stdio_server = threaded_stdio_server

# Paths
BASE_DIR = Path(__file__).parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
RESULTS_DIR = BASE_DIR / "results"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
LEARNING_DB = DATA_DIR / "learning.db"

# Maximum output size to prevent MCP protocol overload
MAX_OUTPUT_CHARS = 500_000

# Tor proxy mode — wraps all tool execution through proxychains4
USE_TOR = os.environ.get("HYDRA_TOR", "0") == "1"
PROXYCHAINS_BIN = shutil.which("proxychains4") or shutil.which("proxychains")

for d in [WORDLISTS_DIR, RESULTS_DIR, REPORTS_DIR, DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────
#  Observability + run recording (Pillars 7 & 8)
#  Guarded imports: the MCP server must keep working
#  even if the `hydra` package is unavailable.
# ──────────────────────────────────────────────
try:
    from hydra.observability import metrics as _metrics
except Exception:  # pragma: no cover - optional dependency
    _metrics = None

try:
    from hydra.observability.run_recorder import record_tool_event as _record_tool_event
except Exception:  # pragma: no cover - optional dependency
    _record_tool_event = None


# ──────────────────────────────────────────────
#  Input validation (Pillar 3 — argument-injection defense)
#
#  _run() executes via subprocess with a LIST and shell=False, so
#  classic SHELL injection is already closed. The remaining risk is
#  ARGUMENT/OPTION injection: a user-supplied value that lands in its
#  own argv slot (the positional args of gau/whatweb/wafw00f/nmap) and
#  starts with '-' is parsed by the tool as a FLAG (e.g. nmap
#  "--script=evil"). Whitespace, newlines and shell metacharacters
#  also have no place in a hostname or URL. Policy: reject such values
#  at the boundary BEFORE the command is ever built.
# ──────────────────────────────────────────────

_HOST_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-]*[A-Za-z0-9])?$")
_HOST_CIDR_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-/]*[A-Za-z0-9])?$")
# URLs: must be http(s); '&', '?', '=' are legitimate query syntax and are
# allowed (harmless under shell=False). Whitespace/quotes/backtick/redirection
# characters are rejected.
_URL_RE = _re.compile(r"^https?://[^\s`'\"\\<>|;]+$", _re.IGNORECASE)
_DNS_RECORD_TYPES = {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr", "srv", "caa", "any"}


def _err(msg: str) -> dict:
    """Boundary-rejection result, shaped like a _run() failure."""
    return {"success": False, "error": msg, "output": "", "rejected": True}


def _validate_host(value: str, allow_cidr: bool = False) -> Optional[dict]:
    """Return an error dict if `value` is not a clean hostname/IP, else None."""
    v = (value or "").strip()
    if not v:
        return _err("Empty host/domain value")
    if v.startswith("-"):
        return _err(f"Rejected '{value}': leading '-' looks like a command-line flag, not a host")
    rx = _HOST_CIDR_RE if allow_cidr else _HOST_RE
    if not rx.match(v):
        return _err(f"Rejected '{value}': not a valid hostname/IP "
                    "(whitespace and shell metacharacters are not allowed)")
    return None


def _validate_url(value: str) -> Optional[dict]:
    """Return an error dict if `value` is not a clean http(s) URL, else None."""
    v = (value or "").strip()
    if not v:
        return _err("Empty URL value")
    if v.startswith("-"):
        return _err(f"Rejected '{value}': leading '-' looks like a flag, not a URL")
    if not _URL_RE.match(v):
        return _err(f"Rejected '{value}': must be an http(s) URL with no whitespace or shell metacharacters")
    return None


def _validate_block(value: str, kind: str = "any") -> Optional[dict]:
    """Validate a newline-delimited block of hosts/URLs (stdin/file inputs)."""
    lines = [ln.strip() for ln in (value or "").splitlines() if ln.strip()]
    if not lines:
        return _err("Empty target list")
    for line in lines:
        if kind == "host":
            e = _validate_host(line)
        elif kind == "url":
            e = _validate_url(line)
        else:  # auto: URL if it has a scheme, otherwise host
            e = _validate_url(line) if "://" in line else _validate_host(line)
        if e:
            return _err(f"Invalid entry '{line}': {e['error']}")
    return None


def _finalize(binary: str, cmd: List[str], result: dict, elapsed: float = 0.0) -> dict:
    """Record metrics + run-event for an execution, then return the result.

    Centralises Pillar 8 (observability) and Pillar 7 (replay) so every exit
    path of _run() is instrumented exactly once. Best-effort: telemetry never
    breaks a live operation.
    """
    if _metrics is not None:
        try:
            _metrics.inc_counter("tool_executions_total", labels={"tool": binary})
            if not result.get("success"):
                _metrics.inc_counter("tool_failures_total", labels={"tool": binary})
            _metrics.observe_histogram(
                "tool_latency_seconds",
                float(result.get("elapsed_seconds", elapsed) or elapsed),
                labels={"tool": binary},
            )
        except Exception:  # pragma: no cover
            pass
    if _record_tool_event is not None:
        try:
            _record_tool_event(binary, cmd, result)
        except Exception:  # pragma: no cover
            pass
    return result


def _run(cmd: List[str], timeout: int = 120, stdin_data: Optional[str] = None) -> dict:
    """Compatibility adapter: preserve the MCP facade's policy and telemetry hooks."""
    return _execute_tool(cmd, timeout, stdin_data, finalize=_finalize,
                         use_tor=USE_TOR, proxychains_bin=PROXYCHAINS_BIN,
                         max_output_chars=MAX_OUTPUT_CHARS)


# ══════════════════════════════════════════════
#  RECON TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def subfinder_scan(domain: str, silent: bool = True) -> str:
    """
    Enumerate subdomains for a target domain using subfinder.
    Fast passive subdomain discovery.

    Args:
        domain: Target domain (e.g., "example.com")
        silent: If True, only output subdomains
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    result = _run(cmd, timeout=180)
    if result["success"]:
        subs = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"subdomains": subs, "count": len(subs)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def amass_enum(domain: str, passive: bool = True) -> str:
    """
    Enumerate subdomains using OWASP Amass. More thorough than subfinder
    but slower. Use passive mode for stealth.

    Args:
        domain: Target domain (e.g., "example.com")
        passive: If True, use passive recon only (no active DNS queries)
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["amass", "enum"]
    if passive:
        cmd.append("-passive")
    cmd.extend(["-d", domain])
    result = _run(cmd, timeout=300)
    if result["success"]:
        subs = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"subdomains": subs, "count": len(subs)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def httpx_probe(targets: str, status_code: bool = True, title: bool = True,
                tech_detect: bool = False, follow_redirects: bool = True) -> str:
    """
    Probe URLs/domains for live HTTP services using httpx.
    Pass multiple targets separated by newlines.

    Args:
        targets: One or more URLs/domains, one per line
        status_code: Show HTTP status codes
        title: Show page titles
        tech_detect: Detect web technologies
        follow_redirects: Follow HTTP redirects
    """
    err = _validate_block(targets, kind="any")
    if err:
        return json.dumps(err, indent=2)
    cmd = ["httpx", "-silent"]
    if status_code:
        cmd.append("-sc")
    if title:
        cmd.append("-title")
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-fr")

    result = _run(cmd, timeout=120, stdin_data=targets)
    return json.dumps(result, indent=2)


@mcp.tool()
def katana_crawl(target: str, depth: int = 3, js_crawl: bool = False, timeout: int = 120) -> str:
    """
    Crawl a target website to discover endpoints, URLs, and JS files.
    Uses Katana web crawler.

    Args:
        target: Target URL (e.g., "https://example.com")
        depth: Crawl depth (1-5)
        js_crawl: Also crawl JavaScript files for endpoints
        timeout: Overall subprocess budget in seconds (katana self-terminates ~20s earlier)
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    # Bound the crawl so katana exits on its own before the subprocess kill (which would
    # otherwise discard all output): -ct caps total duration, -timeout per-request,
    # -rl rate-limit, -c concurrency.
    crawl_secs = max(10, timeout - 20)
    cmd = ["katana", "-u", target, "-silent", "-d", str(min(depth, 5)),
           "-timeout", "10", "-ct", str(crawl_secs), "-rl", "150", "-c", "10"]
    if js_crawl:
        cmd.append("-jc")
    result = _run(cmd, timeout=timeout)
    if result["success"]:
        urls = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"endpoints": urls, "count": len(urls)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def gau_urls(domain: str, timeout: int = 120) -> str:
    """
    Fetch known URLs for a domain from Wayback Machine, Common Crawl,
    and other sources using gau (Get All URLs).

    Args:
        domain: Target domain (e.g., "example.com")
        timeout: Overall subprocess budget in seconds; partial output is returned on timeout
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    # Bound per-request time and parallelism; large domains can stream huge corpora, so
    # _run returns partial output on timeout rather than discarding it.
    cmd = ["gau", "--threads", "5", "--timeout", "30", domain]
    result = _run(cmd, timeout=timeout)
    if result["success"]:
        urls = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"urls": urls, "count": len(urls)}, indent=2)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  VULNERABILITY SCANNING TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def nuclei_scan(target: str, severity: str = "low,medium,high,critical",
                tags: str = "", templates: str = "",
                rate_limit: int = 150) -> str:
    """
    Run Nuclei vulnerability scanner against a target.
    Uses community templates to detect known vulnerabilities, misconfigurations,
    exposed panels, default credentials, and more.

    Args:
        target: Target URL (e.g., "https://example.com")
        severity: Comma-separated severities to scan for (low,medium,high,critical)
        tags: Comma-separated template tags to filter (e.g., "cve,sqli,xss")
        templates: Specific template path/ID to use
        rate_limit: Maximum requests per second
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent",
           "-severity", severity, "-rl", str(rate_limit)]
    if tags:
        cmd.extend(["-tags", tags])
    if templates:
        cmd.extend(["-t", templates])

    result = _run(cmd, timeout=600)
    if result["success"]:
        findings = []
        for line in result["output"].strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", ""),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", []),
                    "matcher_name": data.get("matcher-name", ""),
                })
            except json.JSONDecodeError:
                findings.append({"raw": line})
        return json.dumps({
            "findings": findings, "count": len(findings),
            "target": target, "severity_filter": severity,
        }, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def nuclei_scan_list(targets: str, severity: str = "medium,high,critical",
                     tags: str = "", rate_limit: int = 100) -> str:
    """
    Run Nuclei against multiple targets at once. Pass targets one per line.

    Args:
        targets: Multiple target URLs, one per line
        severity: Comma-separated severity filter
        tags: Template tag filter
        rate_limit: Max requests per second
    """
    err = _validate_block(targets, kind="any")
    if err:
        return json.dumps(err, indent=2)
    # Write targets to temp file
    targets_file = RESULTS_DIR / f"targets_{int(time.time())}.txt"
    targets_file.write_text(targets.strip())

    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-silent",
           "-severity", severity, "-rl", str(rate_limit)]
    if tags:
        cmd.extend(["-tags", tags])

    result = _run(cmd, timeout=900)
    targets_file.unlink(missing_ok=True)

    if result["success"]:
        findings = []
        for line in result["output"].strip().split("\n"):
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                findings.append({"raw": line})
        return json.dumps({"findings": findings, "count": len(findings)}, indent=2)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  FUZZING TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "", match_codes: str = "200,301,302,403",
              method: str = "GET", headers: str = "",
              fuzz_mode: str = "directory") -> str:
    """
    Fuzz web endpoints using ffuf. The FUZZ keyword marks the injection point.

    Args:
        url: Target URL with FUZZ keyword (e.g., "https://example.com/FUZZ")
             If no FUZZ keyword, it appends /FUZZ automatically for directory fuzzing.
        wordlist: Path to wordlist file. Uses default common.txt if empty.
        match_codes: HTTP status codes to match (comma-separated)
        method: HTTP method (GET, POST, etc.)
        headers: Custom headers as "Header1:Value1,Header2:Value2"
        fuzz_mode: "directory" adds /FUZZ to URL, "parameter" for param fuzzing
    """
    err = _validate_url(url)
    if err:
        return json.dumps(err, indent=2)
    if "FUZZ" not in url:
        if fuzz_mode == "directory":
            url = url.rstrip("/") + "/FUZZ"
        else:
            url = url + "?FUZZ=test"

    wl = wordlist or str(WORDLISTS_DIR / "common.txt")
    if not Path(wl).exists():
        return json.dumps({"error": f"Wordlist not found: {wl}. Download one first."})

    cmd = ["ffuf", "-u", url, "-w", wl, "-mc", match_codes,
           "-X", method, "-s"]

    if headers:
        for h in headers.split(","):
            cmd.extend(["-H", h.strip()])

    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


@mcp.tool()
def dirsearch_scan(url: str, extensions: str = "php,asp,aspx,jsp,html,js",
                   threads: int = 25) -> str:
    """
    Brute-force directories and files on a web server using dirsearch.

    Args:
        url: Target URL (e.g., "https://example.com")
        extensions: File extensions to search for (comma-separated)
        threads: Number of concurrent threads
    """
    err = _validate_url(url)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads), "-q",
           "--format=json"]
    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  FINGERPRINTING & DETECTION TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def whatweb_detect(target: str, aggression: int = 1) -> str:
    """
    Detect web technologies, CMS, frameworks, and server software
    running on a target using WhatWeb.

    Args:
        target: Target URL (e.g., "https://example.com")
        aggression: Scan intensity (1=stealthy, 3=aggressive)
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["whatweb", target, f"--aggression={aggression}", "--color=never"]
    result = _run(cmd, timeout=60)
    return json.dumps(result, indent=2)


@mcp.tool()
def wafw00f_detect(target: str) -> str:
    """
    Detect Web Application Firewalls (WAFs) protecting a target.
    Identifies specific WAF products (Cloudflare, Akamai, etc.)

    Args:
        target: Target URL (e.g., "https://example.com")
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["wafw00f", target]
    result = _run(cmd, timeout=60)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "service",
              scripts: str = "") -> str:
    """
    Network port scanning and service detection using nmap.

    Args:
        target: Target hostname or IP
        ports: Port range (e.g., "80,443", "1-1000", "top1000")
        scan_type: "quick" (SYN scan), "service" (version detection), "full" (all ports)
        scripts: Nmap scripts to run (e.g., "http-headers,ssl-cert")
    """
    # nmap takes a host/IP/CIDR positional arg — a value beginning with '-'
    # would be parsed as a flag (e.g. --script=evil), so validate strictly.
    err = _validate_host(target, allow_cidr=True)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["nmap"]
    if scan_type == "quick":
        cmd.extend(["-sS", "-T4"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-T3"])
    elif scan_type == "full":
        cmd.extend(["-sV", "-sC", "-T3"])

    if ports == "top1000":
        cmd.append("--top-ports=1000")
    else:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", scripts])

    cmd.append(target)
    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  WORKFLOW & ANALYSIS TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def full_recon(domain: str) -> str:
    """
    Run a comprehensive recon pipeline on a domain.
    Performs: subdomain enum → HTTP probe → tech detection.
    Returns consolidated results.

    Args:
        domain: Target domain (e.g., "example.com")
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    results = {"domain": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    # Step 1: Subdomain enumeration
    print("[HYDRA] Step 1/3: Subdomain enumeration...", file=sys.stderr)
    sub_result = _run(["subfinder", "-d", domain, "-silent"], timeout=180)
    subdomains = []
    if sub_result["success"]:
        subdomains = [ln.strip() for ln in sub_result["output"].strip().split("\n")
                      if ln.strip()]
    results["subdomains"] = subdomains
    results["subdomain_count"] = len(subdomains)

    # Step 2: HTTP probe
    if subdomains:
        print("[HYDRA] Step 2/3: HTTP probing...", file=sys.stderr)
        probe_input = "\n".join(subdomains)
        probe_result = _run(["httpx", "-silent", "-sc", "-title"],
                           timeout=120, stdin_data=probe_input)
        live_hosts = []
        if probe_result["success"]:
            live_hosts = [ln.strip() for ln in probe_result["output"].strip().split("\n")
                         if ln.strip()]
        results["live_hosts"] = live_hosts
        results["live_count"] = len(live_hosts)
    else:
        results["live_hosts"] = []
        results["live_count"] = 0

    # Step 3: Tech detection on main domain
    print("[HYDRA] Step 3/3: Technology detection...", file=sys.stderr)
    url = f"https://{domain}"
    tech_result = _run(["whatweb", url, "--color=never"], timeout=60)
    results["technologies"] = tech_result.get("output", "")

    return json.dumps(results, indent=2)


@mcp.tool()
def check_tools() -> str:
    """
    Check which security tools are installed and available.
    Returns the availability status of each tool.
    """
    tools = {
        "subfinder": "Subdomain enumeration",
        "amass": "DNS enumeration",
        "httpx": "HTTP probing",
        "nuclei": "Vulnerability scanning",
        "ffuf": "Web fuzzing",
        "katana": "Web crawling",
        "gau": "URL gathering",
        "hakrawler": "Web crawling",
        "dnsx": "DNS resolution & enumeration",
        "subzy": "Subdomain takeover detection",
        "whatweb": "Tech fingerprinting",
        "wafw00f": "WAF detection",
        "nmap": "Network scanning",
        "dirsearch": "Directory brute-forcing",
        "sqlmap": "SQL injection",
        "dalfox": "XSS scanning",
        "gxss": "XSS parameter reflection grep",
        # Post-exploitation & impact (gated, authorized-engagement, PoC-only)
        "nxc": "netexec — lateral movement / AD assessment",
        "impacket-secretsdump": "Credential-store dump (SAM/LSA/NTDS)",
        "enum4linux-ng": "SMB/AD enumeration",
        "smbmap": "SMB share enumeration + permissions",
        "ldapsearch": "LDAP/AD directory query",
        "bloodhound-python": "AD attack-path collection",
        "hashcat": "Offline hash cracking (GPU)",
        "john": "Offline hash cracking (John the Ripper)",
    }

    # Some binaries ship under alternate casing/names; check known aliases too.
    aliases = {
        "gxss": ["gxss", "Gxss"],
    }

    status = {}
    available = 0
    for tool, desc in tools.items():
        candidates = aliases.get(tool, [tool])
        path = next((shutil.which(c) for c in candidates if shutil.which(c)), None)
        status[tool] = {
            "available": path is not None,
            "path": path or "NOT FOUND",
            "description": desc,
        }
        if path:
            available += 1

    return json.dumps({
        "tools": status,
        "available": available,
        "total": len(tools),
        "summary": f"{available}/{len(tools)} tools installed",
    }, indent=2)


@mcp.tool()
def save_finding(title: str, severity: str, target: str,
                 description: str, evidence: str = "",
                 finding_type: str = "unknown") -> str:
    """
    Save a validated vulnerability finding to the HYDRA knowledge base
    for learning and future reference.

    Args:
        title: Short title of the finding
        severity: Severity level (critical, high, medium, low, info)
        target: Affected URL or host
        description: Detailed description of the vulnerability
        evidence: Proof/evidence of the vulnerability
        finding_type: Type of vulnerability (xss, sqli, ssrf, etc.)
    """
    conn = sqlite3.connect(str(LEARNING_DB))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, severity TEXT, target TEXT,
            description TEXT, evidence TEXT, finding_type TEXT,
            created_at REAL
        )
    """)
    conn.execute(
        """INSERT INTO findings (title, severity, target, description,
           evidence, finding_type, created_at) VALUES (?,?,?,?,?,?,?)""",
        (title, severity, target, description, evidence, finding_type, time.time()),
    )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()

    return json.dumps({
        "saved": True, "title": title, "severity": severity,
        "total_findings_stored": count,
    }, indent=2)


@mcp.tool()
def get_findings(severity: str = "", limit: int = 50) -> str:
    """
    Retrieve saved vulnerability findings from the knowledge base.

    Args:
        severity: Filter by severity (empty = all)
        limit: Maximum number of findings to return
    """
    conn = sqlite3.connect(str(LEARNING_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, severity TEXT, target TEXT,
            description TEXT, evidence TEXT, finding_type TEXT,
            created_at REAL
        )
    """)

    if severity:
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,),
        ).fetchall()

    findings = [dict(r) for r in rows]
    conn.close()
    return json.dumps({"findings": findings, "count": len(findings)}, indent=2)


@mcp.tool()
def generate_report(target: str, findings_json: str,
                    report_format: str = "markdown") -> str:
    """
    Generate a structured bug bounty report from findings.

    Args:
        target: Target that was assessed
        findings_json: JSON string with array of findings
        report_format: "markdown" or "json"
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid findings JSON"})

    scan_id = f"scan-{int(time.time())}"
    report_dir = REPORTS_DIR / scan_id
    report_dir.mkdir(parents=True, exist_ok=True)

    if report_format == "markdown":
        lines = [
            "# HYDRA Security Assessment Report",
            f"## Target: {target}",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Findings:** {len(findings)}",
            "",
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f"### {i}. {f.get('title', f.get('name', 'Finding'))}",
                f"- **Severity:** {f.get('severity', 'unknown').upper()}",
                f"- **Host:** {f.get('host', f.get('matched_at', target))}",
                f"- **Type:** {f.get('type', f.get('template_id', 'N/A'))}",
                f"- **Description:** {f.get('description', 'N/A')}",
                "",
            ])

        report_content = "\n".join(lines)
        report_path = report_dir / "report.md"
        report_path.write_text(report_content, encoding="utf-8")
    else:
        report_content = json.dumps({
            "target": target, "scan_id": scan_id,
            "findings": findings, "count": len(findings),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, indent=2)
        report_path = report_dir / "report.json"
        report_path.write_text(report_content, encoding="utf-8")

    return json.dumps({
        "report_path": str(report_path),
        "scan_id": scan_id,
        "format": report_format,
        "findings_count": len(findings),
    }, indent=2)


# ══════════════════════════════════════════════
#  TOOL 18 — sqlmap (SQL Injection)
# ══════════════════════════════════════════════

@mcp.tool()
def sqlmap_scan(
    target: str,
    level: int = 1,
    risk: int = 1,
    technique: str = "",
    tamper: str = "",
    batch: bool = True,
    timeout: int = 120,
) -> str:
    """
    Run sqlmap for automated SQL injection detection and exploitation.

    Args:
        target: Target URL with injectable parameter (e.g. http://example.com/page?id=1)
        level: Level of tests (1-5, higher = more tests, slower)
        risk: Risk of tests (1-3, higher = more aggressive)
        technique: Specific techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
        tamper: Tamper scripts (e.g. "space2comment,between")
        batch: Non-interactive mode (auto-answer Yes to all)
        timeout: Execution timeout in seconds
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["sqlmap", "-u", target, f"--level={level}", f"--risk={risk}",
           "--output-dir", str(RESULTS_DIR / "sqlmap")]
    if batch:
        cmd.append("--batch")
    if technique:
        cmd.extend(["--technique", technique])
    if tamper:
        cmd.extend(["--tamper", tamper])

    return json.dumps(_run(cmd, timeout=timeout), indent=2)


# ══════════════════════════════════════════════
#  TOOL 19 — dalfox (XSS Scanner)
# ══════════════════════════════════════════════

@mcp.tool()
def dalfox_scan(
    target: str,
    pipe_mode: bool = False,
    blind: str = "",
    timeout: int = 120,
) -> str:
    """
    Run dalfox for parameter analysis and XSS scanning.

    Args:
        target: Target URL for XSS testing
        pipe_mode: If true, target is treated as newline-delimited URLs via stdin
        blind: Blind XSS callback URL (your.xss.ht endpoint)
        timeout: Execution timeout in seconds
    """
    err = _validate_block(target, kind="any") if pipe_mode else _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    if pipe_mode:
        cmd = ["dalfox", "pipe", "--silence", "--format", "json"]
        result = _run(cmd, timeout=timeout, stdin_data=target)
    else:
        cmd = ["dalfox", "url", target, "--silence", "--format", "json"]
        if blind:
            cmd.extend(["--blind", blind])
        result = _run(cmd, timeout=timeout)

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 20 — gxss (XSS Parameter Grep)
# ══════════════════════════════════════════════

@mcp.tool()
def gxss_check(
    urls: str,
    timeout: int = 60,
) -> str:
    """
    Run gxss to check which URL parameters are reflected in response (XSS candidates).

    Args:
        urls: Newline-delimited URLs with parameters to check
        timeout: Execution timeout in seconds
    """
    err = _validate_block(urls, kind="url")
    if err:
        return json.dumps(err, indent=2)
    # Binary ships as "Gxss" (capital G) on Kali; some installs use "gxss".
    gxss_bin = shutil.which("gxss") or shutil.which("Gxss") or "Gxss"
    cmd = [gxss_bin]
    result = _run(cmd, timeout=timeout, stdin_data=urls)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 21 — dnsx (DNS Resolution & Enumeration)
# ══════════════════════════════════════════════

@mcp.tool()
def dnsx_resolve(
    target: str,
    record_type: str = "A",
    wordlist: str = "",
    timeout: int = 60,
) -> str:
    """
    Run dnsx for fast DNS resolution and enumeration.

    Args:
        target: Domain or newline-delimited list of subdomains
        record_type: DNS record type: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, ANY
        wordlist: Optional wordlist for brute-force subdomain enumeration
        timeout: Execution timeout in seconds
    """
    # record_type is interpolated into a flag (f"-{record_type}") — constrain it
    # to a known DNS record-type allowlist so it cannot smuggle other options.
    if record_type.lower() not in _DNS_RECORD_TYPES:
        return json.dumps(_err(
            f"Rejected record_type '{record_type}': must be one of "
            f"{sorted(_DNS_RECORD_TYPES)}"), indent=2)
    block_err = _validate_host(target) if wordlist else _validate_block(target, kind="any")
    if block_err:
        return json.dumps(block_err, indent=2)
    cmd = ["dnsx", "-silent", f"-{record_type.lower()}", "-resp"]

    if wordlist:
        cmd.extend(["-w", wordlist, "-d", target])
        result = _run(cmd, timeout=timeout)
    else:
        # Pipe mode: feed subdomains via stdin
        cmd.append("-l")
        cmd.append("-")
        result = _run(cmd, timeout=timeout, stdin_data=target)

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 22 — hakrawler (Fast Web Crawler)
# ══════════════════════════════════════════════

@mcp.tool()
def hakrawler_crawl(
    target: str,
    depth: int = 2,
    scope: str = "subs",
    plain: bool = True,
    timeout: int = 90,
) -> str:
    """
    Run hakrawler for fast web crawling and endpoint discovery.

    Args:
        target: Target URL to crawl
        depth: Crawl depth (1-5)
        scope: Crawl scope: strict (same host), subs (include subdomains), fuzzy (all related)
        plain: Output plain URLs only
        timeout: Execution timeout in seconds
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    # hakrawler reads the seed URL from STDIN; it has no -url/-depth/-scope/-plain flags.
    # Valid flags: -d depth, -subs (include subdomains), -u unique, -timeout, -json.
    cmd = ["hakrawler", "-d", str(depth), "-timeout", str(timeout), "-u"]
    if scope in ("subs", "fuzzy"):
        cmd.append("-subs")
    if not plain:
        cmd.append("-json")

    # Headroom beyond hakrawler's own per-URL crawl timeout so it self-terminates.
    result = _run(cmd, timeout=timeout + 15, stdin_data=target)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 23 — subzy (Subdomain Takeover Detection)
# ══════════════════════════════════════════════

@mcp.tool()
def subzy_takeover(
    targets: str,
    https: bool = True,
    concurrency: int = 10,
    req_timeout: int = 10,
    timeout: int = 180,
) -> str:
    """
    Check subdomains for takeover vulnerabilities using subzy. Feed the output of
    subfinder_scan/amass_enum (newline-delimited subdomains, ideally the live ones
    from httpx_probe) and surface any that point at an unclaimed third-party service
    (GitHub Pages, S3, Heroku, Azure, etc.) — a classic high-value bug-bounty finding.

    Passive fingerprinting against a known service-signature set: it identifies
    dangling CNAMEs, it does NOT claim or modify any resource. Confirm a positive
    by replaying the fingerprint before reporting (single-signal until verified).

    Args:
        targets: One or more subdomains, one per line
        https: Force https for targets with no scheme
        concurrency: Number of concurrent checks (default 10)
        req_timeout: Per-request timeout in seconds (default 10)
        timeout: Overall execution timeout in seconds
    """
    err = _validate_block(targets, kind="host")
    if err:
        return json.dumps(err, indent=2)
    hosts = [ln.strip() for ln in targets.splitlines() if ln.strip()]

    # subzy reads a file via --targets; write the validated hosts to a temp file
    # rather than risk an over-long --target argv on large enumeration lists.
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="subzy_", delete=False)
    try:
        tmp.write("\n".join(hosts))
        tmp.close()
        cmd = ["subzy", "run", "--targets", tmp.name, "--hide_fails",
               "--concurrency", str(concurrency), "--timeout", str(req_timeout)]
        if https:
            cmd.append("--https")
        result = _run(cmd, timeout=timeout)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:  # pragma: no cover
            pass

    if result["success"]:
        # subzy marks a live takeover candidate with the bracketed token
        # "[ VULNERABLE ]" (vs "[ NOT VULNERABLE ]" and the "--hide_fails" banner).
        # Match that exact token so the banner/negatives don't slip through.
        lines = [ln.strip() for ln in result["output"].splitlines() if ln.strip()]
        vulnerable = [ln for ln in lines if "[ VULNERABLE ]" in ln.upper()]
        return json.dumps({
            "checked": len(hosts),
            "vulnerable": vulnerable,
            "vulnerable_count": len(vulnerable),
            "note": "Single-signal fingerprint — replay/verify before reporting.",
            "raw": result["output"],
        }, indent=2)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  KNOWLEDGE OS TOOLS (Phase A — pure-python, no subprocess, offline-first)
#  These expose the hydra.knowledge / hydra.capabilities / hydra.recon_fusion
#  layer. Guarded import: the security tools above keep working even if the
#  knowledge layer is unavailable.
# ══════════════════════════════════════════════

try:
    from hydra.capabilities import CapabilityRegistry, ExecutionPolicy
    from hydra.knowledge.discovery import (
        ChainDiscovery,
        DiscoveryError,
        PatternDiscovery,
        confirm_candidate as _confirm_candidate,
    )
    from hydra.agents.planner import AgentIntelligence, AgentPlanner, AgentRouter
    from hydra.agents.registry import AgentRegistry
    from hydra.runtime.engine import RuntimeEngine, RuntimeIntelligence
    from hydra.runtime.workflows import WorkflowStateError, WorkflowStore
    from hydra.knowledge.governance import (
        DriftDetector,
        GovernanceIntelligence,
        KnowledgeQualityAnalyzer,
    )
    from hydra.adapters.adapter_registry import AdapterRegistry
    from hydra.adapters.intelligence import (
        AdapterIntelligence,
        CapabilityExerciseAnalyzer,
        RuntimeAnalytics,
    )
    from hydra.adapters.selection import AdapterSelector
    from hydra.intelligence.simulation import (
        AgentSimulation,
        CapabilityImpactAnalyzer,
        OutcomePredictor,
        PredictionAnalytics,
        SimulationContext,
        StrategyComparator,
        WorkflowOptimizationAdvisor,
        WorkflowSimulator,
    )
    from hydra.capabilities.dependency_graph import (
        CapabilityDependencyGraph,
        DependencyIntelligence,
    )
    from hydra.plugins.ecosystem import CapabilityMarketplace, EcosystemAnalyzer
    from hydra.plugins.health import PluginHealthAnalyzer
    from hydra.plugins.ownership import AgentOwnershipResolver
    from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
    from hydra.plugins.plugin_registry import PluginRegistry as _PluginRegistry
    from hydra.federation.consensus import ConsensusEngine as _ConsensusEngine
    from hydra.federation.digest import KnowledgeDigestGenerator as _DigestGenerator
    from hydra.federation.intelligence import IntelligenceMesh as _IntelligenceMesh
    from hydra.federation.marketplace import FederationMarketplace as _FederationMarketplace
    from hydra.federation.registry import FederationRegistry as _FederationRegistry
    from hydra.federation.safety import FederationSafetyError as _FederationSafetyError
    from hydra.federation.store import KnowledgeExchangeStore as _ExchangeStore
    from hydra.temporal_intel.context import TemporalContext as _TemporalContext
    from hydra.temporal_intel.forecast import TemporalForecastEngine as _TemporalForecast
    from hydra.temporal_intel.intelligence import TemporalIntelligence as _TemporalIntelligence
    from hydra.temporal_intel.trends import MomentumAnalyzer as _MomentumAnalyzer
    from hydra.temporal_intel.trends import TrendAnalyzer as _TrendAnalyzer
    from hydra.offensive_intel.intelligence import OffensiveIntelligence as _OffensiveIntelligence
    from hydra.campaigns.intelligence import CampaignIntelligence as _CampaignIntelligence
    from hydra.skill_intel.intelligence import SkillGraphIntelligence as _SkillGraphIntelligence
    from hydra.opportunity_intel.intelligence import OpportunityIntelligence as _OpportunityIntelligence
    from hydra.adversary_intel.intelligence import AdversaryIntelligence as _AdversaryIntelligence
    from hydra.threat_intel.intelligence import ThreatIntelligence as _ThreatIntelligence
    from hydra.authorization import (
        BugBountyAuthorizationGate as _AuthGate,
    )
    from hydra.attack.workflow import AttackWorkflow as _AttackWorkflow
    from hydra.attack.waf_bypass import Bypass403Generator as _Bypass403
    from hydra.attack.payloads import (
        PayloadContext as _PayloadContext,
        PayloadLibrary as _PayloadLibrary,
        VulnClass as _VulnClass,
    )
    from hydra.attack.oob import ListenerConfig as _ListenerConfig, OOBCorrelator as _OOBCorrelator
    from hydra.attack.queue import AttackQueue as _AttackQueue
    from hydra.attack_runtime import (
        BrowserConfirmer as _BrowserConfirmer,
        HttpExecutor as _HttpExecutor,
        InteractshClient as _InteractshClient,
        LoginFlow as _LoginFlow,
        OOBAttackTester as _OOBAttackTester,
        OOBConfirmer as _OOBConfirmer,
        OOBPoller as _OOBPoller,
        ScopeLoader as _ScopeLoader,
        SessionContext as _SessionContext,
    )
    from hydra.attack.stored import StoredVulnTester as _StoredVulnTester
    from hydra.attack.param_mining import (
        JSEndpointExtractor as _JSEndpointExtractor,
        ParameterMiner as _ParameterMiner,
    )
    from hydra.attack.poc_bundle import (
        FindingReverifier as _FindingReverifier,
        build_bundle as _build_bundle,
    )
    from hydra.attack.correlate import FindingCorrelator as _FindingCorrelator
    from hydra.attack.auth_session import (
        CookieAuditor as _CookieAuditor,
        CSRFTester as _CSRFTester,
        PasswordResetPoisoning as _PasswordResetPoisoning,
    )
    from hydra.attack.fingerprint_select import FingerprintPayloadSelector as _FingerprintSelector
    from hydra.attack.chain_exec import ChainExecutor as _ChainExecutor
    from hydra.attack.report_builder import AttackReporter as _AttackReporter
    from hydra.attack.graphql import GraphQLTester as _GraphQLTester
    from hydra.attack.jwt_attacks import JWTAnalyzer as _JWTAnalyzer
    from hydra.attack.web_probes import (
        CachePoisonProbe as _CachePoison,
        CORSProbe as _CORSProbe,
        HostHeaderProbe as _HostHeader,
        SmugglingPlan as _SmugglingPlan,
    )
    from hydra.attack.rbac import PrivilegeEscalationTester as _PrivEsc
    from hydra.attack.api_top10 import APIAttackTester as _APIAttackTester
    from hydra.attack.auth_protocol import OAuthTester as _OAuthTester, SAMLAnalyzer as _SAMLAnalyzer
    from hydra.attack.knowledge_loop import FindingPublisher as _FindingPublisher
    from hydra.attack.campaign import AttackCampaign as _AttackCampaign
    from hydra.attack_runtime.race import RaceTester as _RaceTester
    from hydra.capabilities.capability_catalog import CapabilityCatalog
    from hydra.capabilities.source_learning import SourceLearningStore
    from hydra.capabilities.source_selection import AdaptiveSourceSelector
    from hydra.capabilities.tool_capabilities import ToolCapabilityRegistry
    from hydra.capabilities.tool_selection import CapabilityCoverage, ToolSelector
    from hydra.knowledge.verification import (
        ValidationIntelligence,
        VerificationLearningStore,
        VerificationPlaybookGenerator,
    )
    from hydra.recon_fusion.recon_planner import ReconPlanner
    from hydra.knowledge.graph_index import KnowledgeGraphIndex
    from hydra.knowledge.graph_index import rebuild as _kb_rebuild
    from hydra.knowledge.memory import OffensiveMemory
    from hydra.knowledge.opportunity import (
        OpportunityScorer,
        record_fusion_discoveries as _record_fusion_discoveries,
    )
    from hydra.knowledge.opportunity import record_outcome as _record_outcome
    from hydra.knowledge.promotion import PromotionError, apply_promotion
    from hydra.knowledge.report_intel import ReportIntelligencePipeline, ReportSource
    from hydra.knowledge.schema import NodeType as _NodeType
    from hydra.knowledge.schema import Stage as _Stage
    from hydra.knowledge.wiki_store import WikiStore
    from hydra.recon_fusion import ReconFusionPipeline
    _KB_OK = True
except Exception as _kb_err:  # pragma: no cover - knowledge layer optional
    _KB_OK = False
    _KB_IMPORT_ERROR = str(_kb_err)


def _kb_guard():
    if not _KB_OK:
        return json.dumps({"success": False, "error": f"knowledge layer unavailable: {_KB_IMPORT_ERROR}"})
    return None


@mcp.tool()
def capability_list() -> str:
    """List declared reconnaissance capabilities and their outputs (capability-first model)."""
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    caps = []
    for name in reg.names():
        c = reg.get(name)
        caps.append({"capability": name, "outputs": c.outputs,
                     "source_count": len(c.sources), "description": c.description})
    return json.dumps({"capabilities": caps, "count": len(caps)}, indent=2)


@mcp.tool()
def capability_sources(capability: str, online: bool = False) -> str:
    """List a capability's sources with metadata and whether each is runnable under the current policy.

    Args:
        capability: capability name (e.g. "discover_subdomains")
        online: if True, evaluate runnability under online policy (keys from HYDRA_SOURCE_KEYS)
    """
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    cap = reg.get(capability)
    if not cap:
        return json.dumps({"success": False, "error": f"unknown capability: {capability}"})
    policy = _policy(online)
    sources = [{**s.to_dict(), "runnable": s.runnable(policy)} for s in cap.sources]
    return json.dumps({"capability": capability, "policy": policy.mode,
                       "sources": sources, "count": len(sources)}, indent=2)


@mcp.tool()
def recon_fuse(domain: str, capability: str = "discover_subdomains", online: bool = False) -> str:
    """Run the recon knowledge-fusion pipeline (offline-first) and write Asset Intelligence to the wiki.

    Collects from policy-allowed sources, normalizes/dedups, scores confidence by the
    Two-Signal rule, writes canonical wiki asset pages (with backlinks), rebuilds the
    graph index, and attaches prior knowledge from Offensive Memory.

    Args:
        domain: target domain (validated; raw tool output never becomes knowledge directly)
        capability: which capability to fuse (default discover_subdomains)
        online: enable network sources (requires keys; Phase E adapters)
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    try:
        result = ReconFusionPipeline().run(domain, capability, _policy(online), materialize=True)
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    # Phase D: credit contributing sources (discovery side of effectiveness). Derived
    # learning store only — never the wiki; best-effort so fusion never fails on it.
    try:
        _record_fusion_discoveries(result)
    except Exception:
        pass
    priors = [h.to_dict() for h in OffensiveMemory().recall(domain, target=domain, limit=5)]
    return json.dumps({
        "success": True,
        **result.summary(),
        "assets": [a.to_dict() for a in result.assets],
        "materialized_pages": result.materialized,
        "prior_knowledge": priors,
    }, indent=2)


@mcp.tool()
def kb_recall(query: str, types: str = "", target: str = "", limit: int = 10) -> str:
    """Offensive Memory: search-first recall of prior knowledge before planning.

    Args:
        query: free-text query (e.g. "waf bypass cors")
        types: optional comma-separated node types to restrict (technique,pattern,chain,finding,intel,hypothesis)
        target: optional target slug to boost graph-near pages
        limit: max hits
    """
    if (g := _kb_guard()):
        return g
    type_list = None
    if types.strip():
        type_list = []
        for t in types.split(","):
            try:
                type_list.append(_NodeType.from_str(t.strip()))
            except ValueError:
                pass
    hits = OffensiveMemory().recall(query, types=type_list, target=target or None, limit=limit)
    return json.dumps({"query": query, "hits": [h.to_dict() for h in hits], "count": len(hits)}, indent=2)


@mcp.tool()
def kb_lint() -> str:
    """Wiki/graph health check: orphan pages, dangling links, and type breakdown."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    return json.dumps({
        "stats": idx.stats(),
        "orphans": idx.orphans(),
        "dangling_links": [{"from": s, "missing": d} for s, d in idx.dangling_links()],
    }, indent=2)


@mcp.tool()
def kb_promote(page: str, to_stage: str, evidence_count: int = 0, sources: str = "",
               scope_ok: bool = True) -> str:
    """Promote a wiki page up the knowledge hierarchy with hard guardrails.

    Forbidden transitions (e.g. hypothesis→pattern, hypothesis→chain) and missing
    evidence / Two-Signal violations are rejected.

    Args:
        page: page slug
        to_stage: target stage (intel|hypothesis|finding|pattern|chain)
        evidence_count: number of supporting evidence items
        sources: optional comma-separated independent source ids
        scope_ok: whether the target is in scope (required to reach 'finding')
    """
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    wp = store.get(page)
    if wp is None:
        return json.dumps({"success": False, "error": f"page not found: {page}"})
    try:
        stage = _Stage(to_stage.strip().lower())
    except ValueError:
        return json.dumps({"success": False, "error": f"invalid stage: {to_stage}"})
    src_list = [s.strip() for s in sources.split(",") if s.strip()]
    try:
        apply_promotion(wp, stage, sources=src_list, evidence_count=evidence_count, scope_ok=scope_ok)
    except PromotionError as e:
        return json.dumps({"success": False, "rejected": True, "reason": str(e)})
    store.write_page(wp)
    return json.dumps({"success": True, "page": page, "promoted_to": stage.value})


@mcp.tool()
def kb_rebuild_index() -> str:
    """Rebuild the derived graph index from the canonical wiki (the index is disposable)."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"success": True, "stats": _kb_rebuild(WikiStore())}, indent=2)


@mcp.tool()
def asset_lookup(asset: str) -> str:
    """Look up a discovered asset's intelligence (confidence, sources, related links) from the wiki."""
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    page = store.get(asset, _NodeType.ASSET)
    if page is None:
        return json.dumps({"success": False, "error": f"no asset page for: {asset}"})
    return json.dumps({
        "success": True, "asset": asset, "path": str(page.path),
        "confidence": page.meta.get("confidence"), "sources": page.meta.get("sources", []),
        "scope_status": page.meta.get("scope_status"),
        "related": [s for s in page.links],
    }, indent=2)


@mcp.tool()
def graph_neighbors(page: str) -> str:
    """Return the knowledge-graph neighbors (inbound + outbound links) of a wiki page."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    if page not in idx.nodes:
        return json.dumps({"success": False, "error": f"page not in graph: {page}"})
    return json.dumps({
        "page": page, "type": idx.nodes.get(page),
        "neighbors": idx.neighbors(page),
        "related_findings": idx.related_findings(page),
        "related_patterns": idx.related_patterns(page),
        "related_chains": idx.related_chains(page),
    }, indent=2)


@mcp.tool()
def graph_path(source_page: str, target_page: str) -> str:
    """Return the shortest path between two knowledge-graph nodes (offensive leverage discovery)."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    path = idx.shortest_path(source_page, target_page)
    return json.dumps({"from": source_page, "to": target_page,
                       "path": path, "length": max(0, len(path) - 1), "reachable": bool(path)}, indent=2)


@mcp.tool()
def discover_patterns(min_support: int = 2) -> str:
    """Propose recurring-pattern candidates across the wiki (Phase C — DRY-RUN, creates nothing).

    Synthesizes patterns from ≥2 independent weighted evidence sources (validated
    findings + report-intel; hypotheses excluded). Returns ranked candidates with a
    machine-readable `explain` block and a create_new/strengthen_existing recommendation.
    Nothing is written — materialize with `confirm_candidate`.

    Args:
        min_support: minimum independent evidence sources required (>=2).
    """
    if (g := _kb_guard()):
        return g
    cands = PatternDiscovery(WikiStore()).discover(min_support=max(2, min_support))
    return json.dumps({"candidate_type": "pattern", "count": len(cands),
                       "candidates": [c.to_dict() for c in cands]}, indent=2)


@mcp.tool()
def discover_chains(min_support: int = 2) -> str:
    """Propose multi-step chain candidates (Phase C — DRY-RUN, creates nothing).

    Conservative: chains are formed only from a shared target, a shared asset, or an
    explicit graph path between validated findings — never from semantic similarity.
    Returns ranked candidates; materialize with `confirm_candidate`.

    Args:
        min_support: minimum validated-finding steps required (>=2).
    """
    if (g := _kb_guard()):
        return g
    cands = ChainDiscovery(WikiStore()).discover(min_support=max(2, min_support))
    return json.dumps({"candidate_type": "chain", "count": len(cands),
                       "candidates": [c.to_dict() for c in cands]}, indent=2)


@mcp.tool()
def confirm_candidate(candidate_type: str, candidate_id: str) -> str:
    """Explicitly materialize a discovered candidate into a canonical pattern/chain page.

    The only Phase-C write path. Concurrency-safe: re-runs discovery, re-validates the
    candidate by id and the two-signal gate, existence-checks before writing, and on a
    strengthen_existing recommendation merges into the single canonical page. Idempotent.

    Args:
        candidate_type: "pattern" or "chain".
        candidate_id: the id returned by discover_patterns / discover_chains.
    """
    if (g := _kb_guard()):
        return g
    try:
        result = _confirm_candidate(candidate_type, candidate_id, WikiStore())
    except DiscoveryError as e:
        return json.dumps({"success": False, "rejected": True, "reason": str(e)})
    return json.dumps({"success": True, **result}, indent=2)


# ── Phase D — Source Performance Learning & Opportunity Ranking ──────────────────

@mcp.tool()
def record_outcome(candidate_type: str, candidate_id: str, outcome: str) -> str:
    """Record verification feedback for a candidate (Phase D — learning only).

    `outcome` = "confirmed" or "rejected". Attributes the result to the candidate's
    contributing recon sources and appends events to the DERIVED source-learning store.
    Affects source-performance learning ONLY — it never alters promotion rules,
    confidence, or any canonical wiki content.

    Args:
        candidate_type: "pattern" or "chain".
        candidate_id: id from discover_patterns / discover_chains.
        outcome: "confirmed" or "rejected".
    """
    if (g := _kb_guard()):
        return g
    try:
        res = _record_outcome(candidate_type, candidate_id, outcome, WikiStore())
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, **res}, indent=2)


@mcp.tool()
def source_scores(source_id: str = "") -> str:
    """Read derived per-source learning scores (trust / novelty / effectiveness).

    Rebuildable from the raw event log; never canonical. Pass a `source_id` for one
    source, or omit for all sources with recorded history.
    """
    if (g := _kb_guard()):
        return g
    learn = SourceLearningStore()
    if source_id:
        return json.dumps({"source": source_id, "scores": learn.scores(source_id).to_dict()}, indent=2)
    return json.dumps({"sources": [s.to_dict() for s in learn.all_scores()]}, indent=2)


@mcp.tool()
def rank_opportunities(limit: int = 20) -> str:
    """Rank current discovery candidates as investigation opportunities (Phase D).

    Non-canonical OpportunityScore = weighted blend of the candidate's (already-assigned)
    confidence band, contributing-source effectiveness/novelty, chain potential and
    evidence diversity. Read-only; deterministic; confidence.py is never modified.
    """
    if (g := _kb_guard()):
        return g
    ranked = OpportunityScorer(WikiStore()).rank(limit=max(1, limit))
    return json.dumps({"count": len(ranked), "opportunities": [o.to_dict() for o in ranked]}, indent=2)


@mcp.tool()
def prioritization_report() -> str:
    """Knowledge-guided prioritization (Phase D, read-only) — powers future Adaptive Recon.

    Answers: which pattern signatures historically succeed, which source CATEGORIES
    generate confirmed findings, and which evidence-class combinations get accepted.
    All derived from the learning event log; nothing canonical is read or written.
    """
    if (g := _kb_guard()):
        return g
    learn = SourceLearningStore()
    # source.id → category, from the capability registry (kept out of the store).
    reg = CapabilityRegistry().load()
    category_of = {}
    for name in reg.names():
        for s in reg.get(name).sources:
            category_of.setdefault(s.id, s.category.value)
    return json.dumps({
        "successful_patterns": learn.successful_patterns(),
        "effective_source_types": learn.effective_source_types(category_of),
        "accepted_evidence_combos": learn.accepted_evidence_combos(),
    }, indent=2)


# ── Phase E — Adaptive Recon & Autonomous Source Selection (advisory) ────────────

@mcp.tool()
def select_sources(capability: str, online: bool = False, limit: int = 10) -> str:
    """Rank a capability's recon sources using accumulated learning (Phase E — advisory).

    Blends trust / effectiveness (recency-decayed) / novelty / exploration / declared
    prior into a deterministic ranking. Read-only over the derived learning store;
    never modifies confidence, promotion, or the wiki. `runnable` reflects the current
    offline/online policy.

    Args:
        capability: e.g. "discover_subdomains".
        online: evaluate runnability under online policy (keys from HYDRA_SOURCE_KEYS).
        limit: max sources to return.
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = AdaptiveSourceSelector().select(capability, _policy(online), limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "sources": [s.to_dict() for s in ranked]}, indent=2)


@mcp.tool()
def recon_plan(target: str, target_type: str = "web", prior_findings: int = 0,
               online: bool = False) -> str:
    """Produce an advisory, learning-driven reconnaissance plan (Phase E).

    Returns an ordered capability plan with learning-ranked sources, an expected-value
    estimate, and opportunity-driven emphasis. ADVISORY ONLY — it recommends; it never
    executes recon, confirms findings, writes the wiki, or alters confidence/promotion.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code (selects relevant capabilities).
        prior_findings: count of existing findings for the target (caller-supplied; keeps planning O(1)).
        online: plan against online-runnable sources too.
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    plan = ReconPlanner().plan(target, target_type=target_type,
                               prior_findings=max(0, prior_findings), exec_policy=_policy(online))
    return json.dumps({"success": True, **plan.to_dict()}, indent=2)


# ── Phase F — Verification Learning & Validation Intelligence (advisory) ─────────

@mcp.tool()
def record_verification(vuln_class: str, method: str, outcome: str,
                        evidence_type: str = "", evidence_strength: float = 0.0,
                        source_ids: str = "", dedup_key: str = "") -> str:
    """Record how a finding was verified (Phase F — learning only).

    `outcome` = "success" or "failure". Appends to the DERIVED verification-learning
    store. A non-empty `dedup_key` makes the record idempotent. Learning only — never
    confirms a finding, executes a verification, writes the wiki, or alters confidence.

    Args:
        vuln_class: vulnerability class (e.g. "idor").
        method: verification method/tool (e.g. "idor_verifier").
        outcome: "success" | "failure".
        evidence_type: type of evidence used (e.g. "auth_swap_response").
        evidence_strength: 0..1 strength of the evidence.
        source_ids: comma-separated contributing recon source.ids.
        dedup_key: optional idempotency key.
    """
    if (g := _kb_guard()):
        return g
    sids = [s.strip() for s in source_ids.split(",") if s.strip()]
    try:
        newly = VerificationLearningStore().record_verification(
            vuln_class, method, outcome, evidence_type=evidence_type,
            evidence_strength=evidence_strength, source_ids=sids,
            dedup_key=dedup_key or None)
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "recorded": bool(newly), "idempotent_skip": not newly,
                       "vuln_class": vuln_class, "method": method, "outcome": outcome}, indent=2)


@mcp.tool()
def verification_stats() -> str:
    """Validation intelligence (Phase F, read-only): how findings get verified.

    Returns per-method / per-vuln-class / per-evidence-type / per-source-category
    success statistics, derived deterministically from the verification event log.
    """
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    category_of = {}
    for name in reg.names():
        for s in reg.get(name).sources:
            category_of.setdefault(s.id, s.category.value)
    return json.dumps(ValidationIntelligence().summary(category_of), indent=2)


@mcp.tool()
def verification_playbook(vuln_class: str) -> str:
    """Generate an advisory verification playbook for a vulnerability class (Phase F).

    Ranked verification steps (learned methods merged with a static default catalog),
    an expected-verification-value and a confidence-of-success. ADVISORY — it never
    executes a verification or confirms a finding.
    """
    if (g := _kb_guard()):
        return g
    pb = VerificationPlaybookGenerator().generate(vuln_class)
    return json.dumps({"success": True, **pb.to_dict()}, indent=2)


@mcp.tool()
def tool_capabilities(category: str = "") -> str:
    """List the modelled tool-capability catalog (Phase F) — recon/web/cloud/verification.

    Capability modeling for future tool expansion (no integrations). Verification tools
    include their historical effectiveness, read from the derived verification store.

    Args:
        category: optional filter (recon | web | cloud | verification).
    """
    if (g := _kb_guard()):
        return g
    reg = ToolCapabilityRegistry().load()
    vstore = VerificationLearningStore()
    tools = reg.by_category(category) if category else reg.all()
    out = []
    for t in tools:
        eff = reg.effectiveness(t.id, vstore) if t.is_verifier else None
        out.append(t.to_dict(effectiveness=eff))
    return json.dumps({"count": len(out), "categories": reg.categories(), "tools": out}, indent=2)


# ── Phase G — Capability Expansion & Tool Orchestration (read-only) ──────────────

@mcp.tool()
def capability_catalog(category: str = "") -> str:
    """List the capability-centric orchestration catalog v2 (Phase G, read-only).

    Each entry is a CAPABILITY (mapping to interchangeable tools) with its category,
    supported target/finding types, verification coverage, offline-runnable flag and
    confidence weight. Capability modeling only — no integrations/execution.

    Args:
        category: optional filter (reconnaissance|web|api|cloud|source_code|secrets|mobile|infrastructure|verification).
    """
    if (g := _kb_guard()):
        return g
    cat = CapabilityCatalog().load()
    entries = cat.by_category(category) if category else cat.all()
    return json.dumps({
        "count": len(entries), "total_capabilities": cat.count(),
        "categories": cat.categories(), "category_counts": cat.category_counts(),
        "distinct_tools": len(cat.all_tools()),
        "capabilities": [e.to_dict() for e in entries],
    }, indent=2)


@mcp.tool()
def capability_coverage() -> str:
    """Capability coverage intelligence (Phase G, read-only).

    Reports uncovered capabilities, weakest capability areas, over-used tools and
    under-explored tools — derived from the catalog + learning stores. Advisory.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(CapabilityCoverage().report(), indent=2)


@mcp.tool()
def rank_tools(capability: str, limit: int = 10) -> str:
    """Rank a capability's interchangeable tools by accumulated learning (Phase G, read-only).

    Blends recon effectiveness (recency-decayed) + verification effectiveness +
    exploration + trust + the capability's prior. Deterministic given the current time.
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = ToolSelector().rank(capability, limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "tools": [t.to_dict() for t in ranked]}, indent=2)


@mcp.tool()
def select_tool(capability: str) -> str:
    """Select the single best-ranked tool for a capability (Phase G, read-only, advisory)."""
    if (g := _kb_guard()):
        return g
    try:
        best = ToolSelector().select(capability)
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "tool": best.to_dict() if best else None}, indent=2)


# ── Phase H — Multi-Agent Orchestration Layer (read-only, advisory) ──────────────

@mcp.tool()
def agent_catalog() -> str:
    """List the specialized agent definitions (Phase H, read-only).

    Each agent declares responsibilities, allowed capability categories, priority and
    expected outputs. Agents orchestrate the capability layer — they never execute
    tools, confirm findings, or write the wiki.
    """
    if (g := _kb_guard()):
        return g
    reg = AgentRegistry().load()
    return json.dumps({"agent_count": reg.count(),
                       "agents": [a.to_dict() for a in reg.all()]}, indent=2)


@mcp.tool()
def agent_plan(target: str, target_type: str = "web", prior_findings: int = 0) -> str:
    """Produce an advisory, priority-ordered multi-agent workflow for a target (Phase H).

    Returns the ordered agents, the capabilities assigned to each, an expected-value
    estimate and reasoning. ADVISORY — it plans; it never executes or confirms.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code | mobile.
        prior_findings: count of existing findings (caller-supplied; keeps planning O(1)).
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    plan = AgentPlanner().plan(target, target_type=target_type, prior_findings=max(0, prior_findings))
    return json.dumps({"success": True, **plan.to_dict()}, indent=2)


@mcp.tool()
def agent_route(target: str, target_type: str = "web") -> str:
    """Deterministic Target → Agent → Capability → Tool routing (Phase H, read-only).

    Shows, per applicable agent, the capabilities it owns for this target and the
    learning-selected best tool for each. Advisory; nothing is executed.
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    return json.dumps({"success": True, **AgentRouter().route(target, target_type=target_type)}, indent=2)


@mcp.tool()
def agent_coverage() -> str:
    """Agent orchestration intelligence (Phase H, read-only).

    Agent effectiveness, capability ownership (orphans/overlaps), workflow coverage,
    bottlenecks and under-utilized agents — derived from the catalog + learning stores.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(AgentIntelligence().report(), indent=2)


# ── Phase I — Execution Runtime & Workflow Engine (state only; no execution) ─────

@mcp.tool()
def workflow_create(target: str, target_type: str = "web", prior_findings: int = 0) -> str:
    """Create a deterministic PENDING workflow from the agent plan (Phase I).

    Builds the agent→capability→tool plan and persists it as a workflow + tasks in the
    DERIVED runtime store (data/workflows.db). Idempotent (deterministic workflow_id).
    Executes NOTHING — it only records workflow state. Never writes the wiki, confirms
    findings, or runs tools.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code | mobile.
        prior_findings: count of existing findings (caller-supplied; keeps planning O(1)).
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    eng = RuntimeEngine()
    wf_id = eng.create_workflow(target, target_type=target_type, prior_findings=max(0, prior_findings))
    st = eng.workflow_status(wf_id)
    return json.dumps({"success": True, "workflow_id": wf_id,
                       "status": st["workflow"]["status"], "task_count": len(st["tasks"])}, indent=2)


@mcp.tool()
def workflow_status(workflow_id: str) -> str:
    """Read a workflow's current state and its task states (Phase I, read-only)."""
    if (g := _kb_guard()):
        return g
    try:
        return json.dumps({"success": True, **RuntimeEngine().workflow_status(workflow_id)}, indent=2)
    except WorkflowStateError as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
def workflow_history(workflow_id: str = "") -> str:
    """List workflows, or one workflow's task history (Phase I, read-only)."""
    if (g := _kb_guard()):
        return g
    store = WorkflowStore()
    if workflow_id:
        wf = store.get_workflow(workflow_id)
        if wf is None:
            return json.dumps({"success": False, "error": f"unknown workflow: {workflow_id}"})
        return json.dumps({"success": True, "workflow": wf, "tasks": store.get_tasks(workflow_id)}, indent=2)
    return json.dumps({"success": True, "workflows": store.list_workflows()}, indent=2)


@mcp.tool()
def runtime_summary() -> str:
    """Runtime intelligence (Phase I, read-only): workflow/agent/failure/retry/coverage stats."""
    if (g := _kb_guard()):
        return g
    return json.dumps(RuntimeIntelligence().report(), indent=2)


# ── Phase J — Knowledge Governance, Drift Detection & QA (read-only, advisory) ───

@mcp.tool()
def governance_summary() -> str:
    """Knowledge governance summary (Phase J, read-only, advisory).

    Knowledge health score (0-100) + components, drift counts, weakest/healthiest
    areas, graph health, and advisory lifecycle recommendations. Derived from the
    canonical wiki + learning stores; writes nothing and never alters
    confidence/promotion.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(GovernanceIntelligence().governance_summary(), indent=2)


@mcp.tool()
def drift_report() -> str:
    """Knowledge drift report (Phase J, read-only): stale patterns/chains/findings/sources,
    declining source/verification effectiveness, and capability drift — each with
    severity, confidence, rationale and a suggested (advisory) action."""
    if (g := _kb_guard()):
        return g
    return json.dumps(DriftDetector().report(), indent=2)


@mcp.tool()
def knowledge_health() -> str:
    """Deterministic knowledge health score 0-100 with quality metrics (Phase J, read-only)."""
    if (g := _kb_guard()):
        return g
    qa = KnowledgeQualityAnalyzer()
    health = qa.health_score()
    metrics = qa.metrics()
    return json.dumps({
        "score": health.score, "components": health.components,
        "metrics": {k: v for k, v in metrics.items()
                    if k not in ("duplicate_groups", "contradictions")},
    }, indent=2)


@mcp.tool()
def stale_entities() -> str:
    """List stale knowledge entities (patterns/chains/findings/sources) — advisory (Phase J)."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"stale_entities": GovernanceIntelligence().stale_entities()}, indent=2)


@mcp.tool()
def duplicate_patterns() -> str:
    """Report candidate duplicate patterns (same derived signature) for review (Phase J, read-only)."""
    if (g := _kb_guard()):
        return g
    groups = GovernanceIntelligence().duplicate_patterns()
    return json.dumps({"duplicate_groups": groups, "group_count": len(groups)}, indent=2)


@mcp.tool()
def contradiction_report() -> str:
    """Report contradiction candidates — hosts with both validated and rejected findings (Phase J)."""
    if (g := _kb_guard()):
        return g
    contradictions = GovernanceIntelligence().contradiction_report()
    return json.dumps({"contradictions": contradictions, "count": len(contradictions)}, indent=2)


# ── Phase K — Adapter Framework & Sandboxed Tool Integrations (read-only, advisory) ──

@mcp.tool()
def adapter_catalog(capability: str = "", category: str = "") -> str:
    """List synthesized adapter definitions (Phase K, read-only, no execution).

    Adapters are derived deterministically from the capability catalog (one per
    capability×tool). Each carries an execution_profile (safe profiles only),
    timeouts, I/O schemas, and offline/validation/simulation support flags.

    Args:
        capability: optional — only adapters for this capability_id
        category:   optional — only adapters in this category
    """
    if (g := _kb_guard()):
        return g
    reg = AdapterRegistry().load()
    if capability:
        adapters = reg.adapters_for_capability(capability)
    elif category:
        adapters = reg.adapters_for_category(category)
    else:
        adapters = reg.all_adapters()
    return json.dumps({"count": len(adapters), "supported_profiles": reg.supported_profiles(),
                       "adapters": [a.to_dict() for a in adapters]}, indent=2)


@mcp.tool()
def adapter_coverage() -> str:
    """Adapter + capability-exercise coverage (Phase K, read-only).

    Reports adapter coverage over the capability catalog (by category/profile) plus
    capability EXERCISE metrics (declared/owned/has-adapter/exercised/verified) — the
    governance blind spot identified in Phase J."""
    if (g := _kb_guard()):
        return g
    reg = AdapterRegistry().load()
    exercise = CapabilityExerciseAnalyzer(registry=reg).report().to_dict()
    return json.dumps({"adapter_coverage": reg.adapter_coverage(),
                       "capability_exercise": exercise}, indent=2)


@mcp.tool()
def adapter_health(adapter_id: str = "") -> str:
    """Adapter tool-health metrics (Phase K, read-only, derived/rebuildable).

    With an adapter_id: that adapter's health. Without: healthiest + weakest adapters,
    failures and timeouts. Metrics (reliability/runtime/success/failure/timeout) are
    pure functions of the event log under data/tool_health.db.

    Args:
        adapter_id: optional — "<capability_id>::<tool>" (e.g. "port_scanning::nmap")
    """
    if (g := _kb_guard()):
        return g
    from hydra.adapters.tool_health import ToolHealthStore
    if adapter_id:
        return json.dumps(ToolHealthStore().health(adapter_id).to_dict(), indent=2)
    ai = AdapterIntelligence(AdapterRegistry().load())
    return json.dumps({
        "healthiest": ai.healthiest_adapters(), "weakest": ai.weakest_adapters(),
        "failures": ai.adapter_failures(), "timeouts": ai.adapter_timeouts(),
    }, indent=2)


@mcp.tool()
def adapter_summary() -> str:
    """Adapter ecosystem summary (Phase K, read-only): totals, utilization, mean
    reliability, and execution/validation/simulation/success/failure/timeout counts."""
    if (g := _kb_guard()):
        return g
    return json.dumps(AdapterIntelligence(AdapterRegistry().load()).adapter_summary(), indent=2)


@mcp.tool()
def adapter_select(capability: str, limit: int = 5) -> str:
    """Rank a capability's adapters by learning (Phase K, advisory, no execution).

    Combines source-learning effectiveness (recency-decayed), tool-health reliability,
    verification success, trust, an anti-monopoly exploration bonus, and the capability
    prior. Deterministic; ADVISORY — selects, never executes.

    Args:
        capability: capability_id whose adapters to rank
        limit: max adapters to return (default 5)
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = AdapterSelector(AdapterRegistry().load()).rank(capability, limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"capability": capability, "count": len(ranked),
                       "ranked_adapters": [s.to_dict() for s in ranked]}, indent=2)


@mcp.tool()
def runtime_analytics() -> str:
    """Adapter runtime analytics (Phase K, read-only): utilization, average runtime,
    timeout distribution, per-category coverage, and execution-profile distribution."""
    if (g := _kb_guard()):
        return g
    return json.dumps(RuntimeAnalytics(AdapterRegistry().load()).report(), indent=2)


# ── Phase L — Autonomous Knowledge Simulation & Decision Intelligence (read-only) ────

@mcp.tool()
def simulate_workflow(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Simulate a workflow/agent-plan outcome BEFORE execution (Phase L, advisory, no execution).

    Predicts expected findings, verification success, evidence/source diversity, chain &
    pattern generation, and completion probability — purely from historical learning stores.

    Args:
        workflow_id: simulate an existing runtime workflow's capability plan
        target: alternatively, simulate the agent plan for this target
        target_type: web|api|cloud|mobile|network|code (default web)
    """
    if (g := _kb_guard()):
        return g
    sim = WorkflowSimulator(SimulationContext())
    return json.dumps(sim.simulate(workflow_id=workflow_id, target=target,
                                   target_type=target_type).to_dict(), indent=2)


@mcp.tool()
def simulate_strategy(target_type: str = "web") -> str:
    """Compare recon strategies (aggressive/balanced/verification-first) by predicted score,
    confidence, rationale and tradeoffs (Phase L, advisory, simulation only).

    Args:
        target_type: web|api|cloud|mobile|network|code (default web)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(StrategyComparator(SimulationContext()).compare(target_type), indent=2)


@mcp.tool()
def predict_outcome(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Forecast outcome probabilities (Phase L, read-only): success, stale results, new
    patterns, new chains, source bias — from historical events.

    Args:
        workflow_id: an existing runtime workflow
        target: alternatively, the agent plan for this target
        target_type: web|api|cloud|mobile|network|code
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(OutcomePredictor(SimulationContext()).predict(
        workflow_id=workflow_id, target=target, target_type=target_type), indent=2)


@mcp.tool()
def capability_impact(capability: str = "") -> str:
    """Per-capability impact estimate (Phase L, read-only): expected value/findings/
    verification rate/chain & pattern contribution from learning + adapter health.

    Args:
        capability: a capability_id; omit for all capabilities (ranked by expected value)
    """
    if (g := _kb_guard()):
        return g
    an = CapabilityImpactAnalyzer(SimulationContext())
    if capability:
        try:
            return json.dumps(an.impact(capability).to_dict(), indent=2)
        except KeyError as e:
            return json.dumps({"success": False, "error": str(e)})
    impacts = sorted((i.to_dict() for i in an.all_impacts()),
                     key=lambda d: (-d["expected_value"], d["capability_id"]))
    return json.dumps({"count": len(impacts), "capabilities": impacts}, indent=2)


@mcp.tool()
def prediction_accuracy() -> str:
    """Prediction-accuracy framework (Phase L, read-only): forecast accuracy, false
    positive/negative rates, calibration error and drift (predicted vs actual recorded)."""
    if (g := _kb_guard()):
        return g
    return json.dumps(PredictionAnalytics().report(), indent=2)


@mcp.tool()
def agent_effectiveness() -> str:
    """Multi-agent simulation (Phase L, read-only): predicted agent effectiveness,
    bottlenecks, capability overlap and redundancy."""
    if (g := _kb_guard()):
        return g
    return json.dumps(AgentSimulation(SimulationContext()).report(), indent=2)


@mcp.tool()
def workflow_optimization(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Advisory workflow-optimization recommendations (Phase L): remove/reorder steps, add
    capability/verification, increase diversity — WITHOUT mutating any workflow.

    Args:
        workflow_id: an existing runtime workflow
        target: alternatively, the agent plan for this target
        target_type: web|api|cloud|mobile|network|code
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(WorkflowOptimizationAdvisor(SimulationContext()).recommend(
        workflow_id=workflow_id, target=target, target_type=target_type), indent=2)


@mcp.tool()
def decision_health() -> str:
    """Decision-intelligence health (Phase L, read-only): simulation health, prediction
    quality, decision drift, forecast accuracy, and prediction/outcome counts."""
    if (g := _kb_guard()):
        return g
    return json.dumps(PredictionAnalytics().health(), indent=2)


# ── Phase M — Capability Marketplace & Plugin Ecosystem (read-only, advisory) ────────

def _effective_catalog(registry):
    return EffectiveCapabilityCatalog(registry).load()


def _preferred_map(registry):
    return {c["id"]: c["preferred_agent"] for c in registry.plugin_capabilities()
            if c.get("id") and c.get("preferred_agent")}


@mcp.tool()
def plugin_catalog() -> str:
    """List installed/available declarative plugins (Phase M, read-only, no execution).

    Each entry shows id/version/author, capability & tool counts, enabled flag and any
    validation errors. Plugins are declarative data only — never executed."""
    if (g := _kb_guard()):
        return g
    plugins = _PluginRegistry().list_plugins()
    return json.dumps({"count": len(plugins),
                       "enabled": sum(1 for p in plugins if p["enabled"]),
                       "plugins": plugins}, indent=2)


@mcp.tool()
def plugin_summary() -> str:
    """Plugin ecosystem at-a-glance (Phase M, read-only): effective capability/adapter
    composition (core vs plugin) and installed-plugin count."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps({"installed_plugins": len(reg.enabled_plugins()),
                       "composition": eff.composition(),
                       "plugin_ids": sorted(p.plugin_id for p in reg.enabled_plugins())}, indent=2)


@mcp.tool()
def plugin_health() -> str:
    """Derived plugin health (Phase M, read-only, rebuildable): adoption / diversity /
    effectiveness / health from the event-sourced data/plugin_health.db."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"plugins": PluginHealthAnalyzer(_PluginRegistry()).report()}, indent=2)


@mcp.tool()
def plugin_dependencies(plugin_id: str = "") -> str:
    """Capability dependency edges contributed by plugins (Phase M, read-only).

    Args:
        plugin_id: optional — only this plugin's declared edges + plugin version deps
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    if plugin_id:
        pd = reg.get_plugin(plugin_id)
        if pd is None:
            return json.dumps({"success": False, "error": f"unknown plugin: {plugin_id}"})
        return json.dumps({"plugin_id": plugin_id, "dependencies": pd.dependencies,
                           "requires_plugins": pd.requires_plugins}, indent=2)
    return json.dumps({"dependency_edges": reg.plugin_dependency_edges()}, indent=2)


@mcp.tool()
def plugin_capabilities(plugin_id: str = "") -> str:
    """Capabilities a plugin adds to the effective catalog (Phase M, read-only).

    Args:
        plugin_id: optional — only this plugin's capabilities; omit for all plugin capabilities
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    if plugin_id:
        pd = reg.get_plugin(plugin_id)
        if pd is None:
            return json.dumps({"success": False, "error": f"unknown plugin: {plugin_id}"})
        return json.dumps({"plugin_id": plugin_id, "capabilities": pd.capabilities}, indent=2)
    caps = reg.plugin_capabilities()
    return json.dumps({"count": len(caps), "capabilities": caps}, indent=2)


@mcp.tool()
def plugin_coverage() -> str:
    """What the plugin ecosystem adds (Phase M, read-only): capabilities/adapters/agents/
    verification coverage added, plus effective-catalog composition and per-plugin breakdown."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps(EcosystemAnalyzer(reg, eff).report(), indent=2)


@mcp.tool()
def capability_graph() -> str:
    """Capability dependency graph intelligence (Phase M, read-only): edge counts by
    relation, requires-acyclicity + cycles, critical/isolated capabilities, coverage gaps."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    return json.dumps(DependencyIntelligence(graph).report(), indent=2)


@mcp.tool()
def dependency_paths(source: str, target: str) -> str:
    """Shortest directed dependency path source→target over requires+enhances (Phase M).

    Args:
        source: starting capability_id
        target: destination capability_id
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    path = graph.dependency_paths(source, target)
    return json.dumps({"source": source, "target": target,
                       "path": path, "reachable": bool(path)}, indent=2)


@mcp.tool()
def critical_capabilities() -> str:
    """Most-depended-upon (critical) capabilities by `requires` in-degree (Phase M, read-only)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    return json.dumps({"critical_capabilities": graph.critical_capabilities(),
                       "isolated_capabilities": graph.isolated_capabilities()}, indent=2)


@mcp.tool()
def agent_ownership() -> str:
    """Automatic agent ownership of (plugin) capabilities (Phase M, read-only, advisory):
    per-capability owner, candidates and ownership confidence."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps(AgentOwnershipResolver(eff, preferred=_preferred_map(reg)).resolve(), indent=2)


@mcp.tool()
def ownership_conflicts() -> str:
    """Agent ownership conflicts and gaps (Phase M, read-only, advisory)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    res = AgentOwnershipResolver(eff, preferred=_preferred_map(reg)).resolve()
    return json.dumps({"ownership_conflicts": res["ownership_conflicts"],
                       "ownership_conflict_count": res["ownership_conflict_count"],
                       "ownership_gaps": res["ownership_gaps"],
                       "ownership_gap_count": res["ownership_gap_count"]}, indent=2)


@mcp.tool()
def ecosystem_summary() -> str:
    """Full ecosystem intelligence (Phase M, read-only, advisory): what plugins add +
    marketplace recommendations (missing plugins, weak areas, ecosystem gaps)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    ad = AdapterRegistry(catalog=eff).load()
    return json.dumps({"ecosystem": EcosystemAnalyzer(reg, eff, ad).report(),
                       "marketplace": CapabilityMarketplace(reg, eff, ad).recommend()}, indent=2)


# ── Phase N — Federated Knowledge Exchange & Intelligence Mesh ──────────────────
# All ten tools are read-only/deterministic/advisory and exchange AGGREGATED METADATA
# ONLY. They never share wiki pages, evidence, findings, targets, source identities or
# secrets; never execute peers; and never touch promotion.py / confidence.py / the wiki.
# The derived federation ledger lives in data/federation.db (WAL, rebuildable, disposable).

@mcp.tool()
def federation_peers() -> str:
    """List trusted peer Hydra instances (Phase N, read-only, advisory).

    Federation metadata only — peer name, advertised version/protocol, capability &
    adapter counts, categories, plus DERIVED trust score, health and semantic-version
    compatibility. No credentials or secrets are ever stored."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_FederationRegistry().summary(), indent=2)


@mcp.tool()
def federation_summary() -> str:
    """Federation ledger at-a-glance (Phase N, read-only): event counts by type, distinct
    peers, imported/exported digest counts. Pure function of the append-only data/federation.db."""
    if (g := _kb_guard()):
        return g
    store = _ExchangeStore()
    return json.dumps({**store.summary(),
                       "registry": _FederationRegistry(store).summary()["total_peers"]}, indent=2)


@mcp.tool()
def export_digest(node_name: str = "local", record: bool = False) -> str:
    """Generate this node's anonymized, exchangeable knowledge digest (Phase N, read-only).

    Bundles Capability / Source / Verification / Plugin digests — AGGREGATE METADATA ONLY
    (capability ids and abstract category/method labels + derived scores). Deterministic
    (generated_at fixed) so it is rebuild-identical. No raw knowledge ever leaves the node.

    Args:
        node_name: local node identity used to derive the anonymous origin_peer_id
        record: if True, also append a (derived) digest_export event to data/federation.db
    """
    if (g := _kb_guard()):
        return g
    digest = _DigestGenerator(node_name=node_name).generate(now=0.0)
    if record:
        _ExchangeStore().record("digest_export", digest, peer_id=digest["origin_peer_id"])
    return json.dumps({"success": True, "digest": digest}, indent=2)


@mcp.tool()
def import_digest(digest_json: str, peer_id: str = "") -> str:
    """Import a peer's knowledge digest into the derived federation ledger (Phase N).

    The payload is validated to be aggregated metadata only (raw knowledge is rejected) and
    appended idempotently to data/federation.db — NEVER to the canonical wiki, and never
    influencing promotion or confidence. Re-importing an identical digest is a no-op.

    Args:
        digest_json: the peer's digest envelope as a JSON string (from their export_digest)
        peer_id: optional peer id to attribute the import to (else taken from the envelope)
    """
    if (g := _kb_guard()):
        return g
    try:
        digest = json.loads(digest_json)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": f"invalid digest JSON: {e}"})
    if not isinstance(digest, dict):
        return json.dumps({"success": False, "error": "digest must be a JSON object"})
    pid = peer_id or str(digest.get("origin_peer_id", ""))
    try:
        inserted = _ExchangeStore().record("digest_import", digest, peer_id=pid)
    except _FederationSafetyError as e:
        return json.dumps({"success": False, "error": f"rejected (not metadata-only): {e}"})
    return json.dumps({"success": True, "imported": inserted,
                       "deduplicated": not inserted, "peer_id": pid}, indent=2)


@mcp.tool()
def capability_trends() -> str:
    """Federation-wide capability popularity & effectiveness (Phase N, read-only, advisory):
    per-capability adopting-peer count, total exercise, and mean effectiveness across peers."""
    if (g := _kb_guard()):
        return g
    mesh = _IntelligenceMesh()
    return json.dumps({"capabilities": mesh.capability_popularity(),
                       "ecosystem_effectiveness": mesh.ecosystem_effectiveness()}, indent=2)


@mcp.tool()
def verification_trends() -> str:
    """Federation-wide verification trends (Phase N, read-only, advisory): mean method and
    evidence-class success rates aggregated across all imported digests."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_IntelligenceMesh().verification_trends(), indent=2)


@mcp.tool()
def source_trends() -> str:
    """Federation-wide source-CATEGORY trends (Phase N, read-only, advisory): mean
    effectiveness/trust/novelty per source category. No source identities are exchanged."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"source_categories": _IntelligenceMesh().source_category_trends()}, indent=2)


@mcp.tool()
def federation_consensus(capability_id: str = "") -> str:
    """Advisory federation consensus (Phase N, read-only): consensus confidence, disagreement,
    diversity and blended federation confidence — for one capability or the whole federation.

    ADVISORY ONLY — never influences promotion, confidence bands, or wiki state.

    Args:
        capability_id: optional — score just this capability; omit for the full report
    """
    if (g := _kb_guard()):
        return g
    ce = _ConsensusEngine()
    if capability_id:
        return json.dumps(ce.capability_consensus(capability_id), indent=2)
    return json.dumps(ce.consensus_report(), indent=2)


@mcp.tool()
def ecosystem_opportunities() -> str:
    """Advisory federation marketplace (Phase N, read-only): capabilities popular elsewhere
    but missing locally, widely-adopted plugins, underrepresented categories + recommendations.
    Discovery only — nothing is installed, executed, or written."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_FederationMarketplace().ecosystem_opportunities(), indent=2)


@mcp.tool()
def federation_health() -> str:
    """Federation-wide health (Phase N, read-only, advisory): contributing peers, imported
    digests, ecosystem effectiveness, verification effectiveness, registry trust + consensus."""
    if (g := _kb_guard()):
        return g
    store = _ExchangeStore()
    mesh = _IntelligenceMesh(store)
    reg = _FederationRegistry(store)
    consensus = _ConsensusEngine(store).consensus_report(top=5)
    return json.dumps({
        "mesh": mesh.federation_health(),
        "registry": {k: v for k, v in reg.summary().items() if k != "peers"},
        "mean_federation_confidence": consensus["mean_federation_confidence"],
        "advisory": True,
    }, indent=2)


# ── Phase O — Temporal Knowledge Intelligence (derived, advisory, deterministic) ──
# All six tools are read-only/deterministic/advisory and built ENTIRELY from the existing
# derived event logs (source/verification/tool-health/plugin-health/decision/federation).
# They never read or write the canonical wiki and never touch promotion.py / confidence.py.
# `now` is an optional injected reference time for determinism; <=0 means "use newest event".
def _temporal_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def temporal_summary(now: float = 0.0) -> str:
    """Temporal knowledge overview (Phase O, read-only, advisory): temporal-health, strongest/
    weakest trends, emerging/declining capabilities, decay & anomaly counts, recommendations.

    Args:
        now: optional reference timestamp for deterministic bucketing (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().temporal_summary(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_trends(domain: str = "", now: float = 0.0) -> str:
    """Temporal trends + momentum (Phase O, read-only, advisory): rising/stable/declining per
    entity with slope, momentum and the bucket series, for capability/adapter/agent/plugin/
    source/verification.

    Args:
        domain: optional single domain (e.g. "capability"); omit for all trend domains
        now: optional reference timestamp for deterministic bucketing (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    ref = _temporal_now(now)
    ctx = _TemporalContext().load()
    trend, mom = _TrendAnalyzer(ctx), _MomentumAnalyzer(ctx)
    if domain:
        return json.dumps({"domain": domain, "trends": trend.domain_trends(domain, ref),
                           "momentum": mom.domain_momentum(domain, ref)}, indent=2)
    return json.dumps({"trends": trend.trends(ref), "momentum": mom.momentum(ref)}, indent=2)


@mcp.tool()
def temporal_forecast(domain: str = "", now: float = 0.0, horizon: int = 3) -> str:
    """Deterministic bounded forecasts (Phase O, read-only, advisory): future capability
    utilization, verification coverage, source diversity, plugin adoption. Moving-average +
    linear slope; never stochastic.

    Args:
        domain: optional single domain to forecast; omit for the four standard signals
        now: optional reference timestamp (<=0 = newest event)
        horizon: number of future buckets to project (default 3)
    """
    if (g := _kb_guard()):
        return g
    ref = _temporal_now(now)
    fc = _TemporalForecast(_TemporalContext().load())
    if domain:
        return json.dumps({"domain_forecast": fc.domain_forecast(domain, ref, horizon),
                           "entity_forecast": fc.entity_forecast(domain, ref, horizon)}, indent=2)
    return json.dumps(fc.report(ref, horizon), indent=2)


@mcp.tool()
def temporal_decay(now: float = 0.0) -> str:
    """Temporal decay findings (Phase O, read-only, advisory): stale capabilities/adapters/
    plugins/verification methods ranked by severity, each with rationale + suggested action.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().decay_forecast(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_anomalies(now: float = 0.0) -> str:
    """Temporal anomalies (Phase O, read-only, advisory): spikes, drops, inactivity and
    concentration across domains. Findings only — no alerts, no side effects.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().anomaly_report(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_health(now: float = 0.0) -> str:
    """Temporal-health score (Phase O, read-only, advisory): 0-100 blend rewarding rising/active
    knowledge and penalizing decay + anomalies. Never alters confidence/promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().temporal_health(_temporal_now(now)), indent=2)


# ── Phase P — Offensive Capability Intelligence (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory. They SCORE and ADVISE over the
# capability/skill MODEL using the existing derived learning logs + the static declarative
# catalogs; they never exploit, validate, confirm, promote, or execute, and never touch the
# canonical wiki / promotion.py / confidence.py. `now` is optional (<=0 = newest event).
def _offensive_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def offensive_summary(now: float = 0.0) -> str:
    """Offensive intelligence overview (Phase P, read-only, advisory): offensive-health, top &
    underutilized capabilities, strongest attack chains, weak categories, redundant pairs, the
    skill bridge, and bounded recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_summary(_offensive_now(now)), indent=2)


@mcp.tool()
def offensive_effectiveness(capability_id: str = "", now: float = 0.0) -> str:
    """Per-capability offensive effectiveness (Phase P, read-only, advisory): effectiveness,
    utility, contribution, uniqueness, redundancy + explain rationale; ranked, or one capability.

    Args:
        capability_id: optional single capability id; omit for the full ranked list
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_effectiveness(
        capability_id, _offensive_now(now)), indent=2)


@mcp.tool()
def offensive_coverage(category: str = "", now: float = 0.0) -> str:
    """Offensive coverage (Phase P, read-only, advisory): per-category effectiveness / verification
    / exercise, workflow (agent) coverage, and attack-path coverage.

    Args:
        category: optional single category (e.g. "web"); omit for all categories
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_coverage(
        category, _offensive_now(now)), indent=2)


@mcp.tool()
def offensive_chains(target_type: str = "", limit: int = 10, now: float = 0.0) -> str:
    """Attack-chain intelligence (Phase P, read-only, advisory): capability chains scored by
    effectiveness, diversity and popularity from the dependency graph. Bounded; NON-executing —
    it scores the model, it never runs a chain.

    Args:
        target_type: optional seed target-type filter (e.g. "url", "domain")
        limit: max chains to return (default 10)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().attack_chains(
        target_type, max(1, limit), _offensive_now(now)), indent=2)


@mcp.tool()
def offensive_overlap(now: float = 0.0) -> str:
    """Capability overlap / redundancy (Phase P, read-only, advisory): redundant capability pairs
    and clusters (interchangeable capabilities sharing finding types / tools).

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_overlap(_offensive_now(now)), indent=2)


@mcp.tool()
def offensive_gaps(now: float = 0.0) -> str:
    """Offensive coverage gaps (Phase P, read-only, advisory): weak categories, weakly-covered
    finding types, and weak chains (a low-effectiveness link or no verifying terminal).

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_gaps(_offensive_now(now)), indent=2)


@mcp.tool()
def offensive_skills(now: float = 0.0) -> str:
    """Skill intelligence bridge (Phase P, read-only, advisory): Capability→Skill→Workflow→Agent
    mapping with skill effectiveness/quality. It MAPS and SCORES skills — it never executes them.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_skills(_offensive_now(now)), indent=2)


@mcp.tool()
def offensive_health(now: float = 0.0) -> str:
    """Offensive-health score (Phase P, read-only, advisory): 0-100 blend of mean effectiveness +
    structural coverage quality, rewarding learned evidence and lightly penalizing redundancy.
    Never alters confidence / promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OffensiveIntelligence().offensive_health(_offensive_now(now)), indent=2)


# ── Phase Q — Offensive Campaign Reasoning Engine (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory and reason about campaign STRUCTURE only.
# Post-exploitation tactics are MODEL-ONLY (no capabilities, no execution). They never execute,
# touch targets, launch tools, confirm findings, or modify promotion/confidence, and never touch
# the canonical wiki. `now` is optional (<=0 = newest event).
def _campaign_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def campaign_summary(now: float = 0.0) -> str:
    """Campaign intelligence overview (Phase Q, read-only, advisory): campaign-health, the 12-phase
    model (post-exploitation = model-only), workflow graph, playbooks, objectives, recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_summary(_campaign_now(now)), indent=2)


@mcp.tool()
def campaign_objectives(objective: str = "", now: float = 0.0) -> str:
    """Objective mapping (Phase Q, read-only, advisory): Objective → Skills → Capabilities →
    Adapters → Agents, as explainable chains; one objective or all.

    Args:
        objective: optional objective id (e.g. "web_vuln_candidates"); omit for all
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_objectives(objective, _campaign_now(now)), indent=2)


@mcp.tool()
def campaign_playbooks(playbook: str = "", now: float = 0.0) -> str:
    """Campaign playbooks (Phase Q, read-only, advisory): generated playbooks scored by effectiveness;
    a single playbook also exposes campaign_capabilities/skills/agents/dependencies + dual graphs.

    Args:
        playbook: optional playbook id (e.g. "web_application_assessment"); omit for the summary
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_playbooks(playbook, _campaign_now(now)), indent=2)


@mcp.tool()
def campaign_paths(playbook: str = "", target_type: str = "", limit: int = 10, now: float = 0.0) -> str:
    """Capability sequencing / attack-path generation (Phase Q, read-only, advisory): per-playbook
    execution-order sequence + dual graphs, or bounded Phase-P attack chains. NON-executing.

    Args:
        playbook: optional playbook id to sequence; omit for bounded attack chains
        target_type: optional seed target-type filter for chains
        limit: max chains (default 10)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_paths(
        playbook, target_type, max(1, limit), _campaign_now(now)), indent=2)


@mcp.tool()
def campaign_strategies(strategy_a: str = "", strategy_b: str = "", now: float = 0.0) -> str:
    """Strategy comparison (Phase Q, read-only, advisory): two strategies (playbook ids or capability
    categories) scored on coverage / diversity / effectiveness / dependency-risk / redundancy.

    Args:
        strategy_a: first playbook id or category (default: top playbook)
        strategy_b: second playbook id or category (default: 2nd playbook)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_strategies(
        strategy_a, strategy_b, _campaign_now(now)), indent=2)


@mcp.tool()
def campaign_simulation(scenario: str = "remove_capability", subject: str = "", now: float = 0.0) -> str:
    """Counterfactual campaign simulation (Phase Q, read-only, advisory, NON-executing): project the
    campaign impact of remove_capability / remove_plugin / verification_drop / category_change. No
    runtime execution, no target interaction.

    Args:
        scenario: one of remove_capability | remove_plugin | verification_drop | category_change
        subject: the capability / plugin / category the scenario applies to
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_simulation(
        scenario, subject, _campaign_now(now)), indent=2)


@mcp.tool()
def campaign_gaps(now: float = 0.0) -> str:
    """Campaign gaps (Phase Q, read-only, advisory): weak campaign phases + the Phase-P offensive
    gaps, with the model-only (post-exploitation) phases listed explicitly.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_gaps(_campaign_now(now)), indent=2)


@mcp.tool()
def campaign_health(now: float = 0.0) -> str:
    """Campaign-health score (Phase Q, read-only, advisory): 0-100 blend of phase effectiveness,
    playbook effectiveness and phase coverage. Never alters confidence / promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_CampaignIntelligence().campaign_health(_campaign_now(now)), indent=2)


# ── Phase R — Skill Composition & Skill Graph Intelligence (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory. They promote Skills to first-class entities
# (skill dependency + composition graph, bundles, effectiveness, coverage, gaps, marketplace) over a
# load-once SkillContext that reuses the Phase-P OffensiveIntelligence. Store-free. Skills never
# execute, never modify capability/promotion/confidence state, never become a canonical source.
# `now` is optional (<=0 = newest event).
def _skill_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def skill_summary(now: float = 0.0) -> str:
    """Skill intelligence overview (Phase R, read-only, advisory): skill-health, graph stats, top
    skills, bundles, coverage, critical skills, gaps, recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_summary(_skill_now(now)), indent=2)


@mcp.tool()
def skill_graph(now: float = 0.0) -> str:
    """Skill graph (Phase R, read-only, advisory): the skill dependency graph (derived from the
    capability dependency graph) + the skill composition graph (shared capabilities) + clusters.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_graph(_skill_now(now)), indent=2)


@mcp.tool()
def skill_dependencies(now: float = 0.0) -> str:
    """Skill dependency intelligence (Phase R, read-only, advisory): dependency edges, critical
    skills (most depended-upon), isolated skills, and directed cycles.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_dependencies(_skill_now(now)), indent=2)


@mcp.tool()
def skill_bundles(now: float = 0.0) -> str:
    """Skill bundles (Phase R, read-only, advisory): coherent skill bundles (by category) with their
    union of capabilities/agents and a mean effectiveness.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_bundles(_skill_now(now)), indent=2)


@mcp.tool()
def skill_effectiveness(skill_id: str = "", now: float = 0.0) -> str:
    """Per-skill effectiveness (Phase R, read-only, advisory): effectiveness, utility, uniqueness,
    redundancy; ranked, or a single skill.

    Args:
        skill_id: optional single skill id (e.g. "tn_xss"); omit for the full ranked list
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_effectiveness(skill_id, _skill_now(now)), indent=2)


@mcp.tool()
def skill_coverage(now: float = 0.0) -> str:
    """Skill coverage (Phase R, read-only, advisory): per-category skill coverage + overall
    capability coverage (capabilities covered by >=1 skill vs uncovered).

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_coverage(_skill_now(now)), indent=2)


@mcp.tool()
def skill_gaps(now: float = 0.0) -> str:
    """Skill gaps (Phase R, read-only, advisory): capabilities with no skill, weak skills, and
    broken chain_to references.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_gaps(_skill_now(now)), indent=2)


@mcp.tool()
def skill_marketplace(now: float = 0.0) -> str:
    """Skill marketplace (Phase R, read-only, advisory): where the skill ecosystem could grow —
    low-coverage categories and weak skills to strengthen. Advisory only; authors nothing.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_SkillGraphIntelligence().skill_marketplace(_skill_now(now)), indent=2)


# ── Phase S — Opportunity Intelligence (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory. They identify WHERE Hydra's highest-value,
# least-covered, most-leveraged offensive OPPORTUNITIES are, over a load-once OpportunityContext that
# reuses the Phase-P OffensiveIntelligence (threaded into Phase-Q + Phase-R) plus bounded Phase-O
# (emerging) and Phase-N (peer demand) signals. Store-free. The versioned OpportunityScore ranks the
# capability MODEL; it never exploits, validates, confirms, promotes, or executes, and never touches
# the canonical wiki / promotion.py / confidence.py. `now` is optional (<=0 = newest event).
def _opportunity_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def opportunity_summary(now: float = 0.0) -> str:
    """Opportunity intelligence overview (Phase S, read-only, advisory): opportunity-health, the
    attack-surface totals, top opportunities, synthesized coverage, blind spots, graph bottlenecks,
    and bounded recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_summary(_opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_surface(now: float = 0.0) -> str:
    """Attack-surface model (Phase S, read-only, advisory): Hydra's OWN modelled offensive reach by
    category — addressable finding-types/target-types, mean effectiveness, verification capability,
    and how much has been exercised. NON-executing — it models the capability surface, not a target.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_surface(_opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_coverage(now: float = 0.0) -> str:
    """Synthesized coverage (Phase S, read-only, advisory): one fused per-category coverage_index
    over effectiveness / verification / exercise / agent / skill dimensions, plus an overall index.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_coverage(_opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_blindspots(now: float = 0.0) -> str:
    """Blind spots (Phase S, read-only, advisory): severity-ranked gaps fused across layers —
    verification-blind categories, uncovered finding-types, weak chains, capabilities with no skill /
    no agent owner, and INTENTIONAL model-only campaign phases (flagged, never a defect).

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_blindspots(_opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_graph(now: float = 0.0) -> str:
    """Opportunity graph (Phase S, read-only, advisory): the capability <-> finding-type structure +
    dependency edges, with hub capabilities (high leverage) and bottleneck finding-types (fragile,
    single-provider coverage). NON-executing — it scores the MODEL.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_graph(_opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_ranking(capability_id: str = "", limit: int = 25, now: float = 0.0) -> str:
    """Ranked opportunities (Phase S, read-only, advisory): the versioned OpportunityScore per
    capability (value + coverage-deficit + chain-potential + uniqueness + novelty + capped temporal /
    federation bonuses), fully explained; ranked, or a single capability. Distinct from the Phase-D
    `rank_opportunities` (which ranks discovery candidates, not the capability model).

    Args:
        capability_id: optional single capability id; omit for the full ranked list
        limit: max opportunities to return (default 25)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_ranking(
        capability_id, max(1, limit), _opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_advisor(limit: int = 10, now: float = 0.0) -> str:
    """Opportunity recommendations (Phase S, read-only, advisory): bounded, SAFE-verb advice —
    prioritize / strengthen / expand / diversify / investigate / improve. Authors nothing; never
    executes, exploits, attacks, or deploys.

    Args:
        limit: max recommendations to return (default 10)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_advisor(
        max(1, limit), _opportunity_now(now)), indent=2)


@mcp.tool()
def opportunity_health(now: float = 0.0) -> str:
    """Opportunity-health (Phase S, read-only, advisory): a 0-100 score blending synthesized
    coverage, surface breadth, coverage realization, and blind-spot health. Advisory; never alters
    confidence/promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_OpportunityIntelligence().opportunity_health(_opportunity_now(now)), indent=2)


# ── Phase T — Adversary & ATT&CK Intelligence (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory. They model Hydra's offensive tradecraft
# coverage against MITRE ATT&CK over a load-once AdversaryContext that reuses the Phase-P
# OffensiveIntelligence (threaded through Phase-S → Phase-Q/R) plus a bounded Phase-O signal. A
# static declarative AttackMapping ties tactics/techniques to Hydra's real capability categories;
# out-of-scope / post-exploitation tactics are MODEL-ONLY (no capability, no execution). Store-free;
# it never exploits, emulates, validates, confirms, promotes, or executes, and never touches the
# canonical wiki / promotion.py / confidence.py. `now` is optional (<=0 = newest event).
def _adversary_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def adversary_summary(now: float = 0.0) -> str:
    """Adversary/ATT&CK intelligence overview (Phase T, read-only, advisory): adversary-health,
    tactic coverage (Hydra-covered vs model-only), technique coverage by status, best-supported
    adversary profiles, gaps, top capabilities, and bounded recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().adversary_summary(_adversary_now(now)), indent=2)


@mcp.tool()
def attack_tactics(now: float = 0.0) -> str:
    """ATT&CK tactic coverage (Phase T, read-only, advisory): per-tactic covered/weak/uncovered
    technique counts, coverage %, and mean effectiveness. Out-of-scope / post-exploitation tactics
    are flagged MODEL-ONLY (intentionally uncovered, never a defect).

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_tactics(_adversary_now(now)), indent=2)


@mcp.tool()
def attack_techniques(technique_id: str = "", tactic_id: str = "", now: float = 0.0) -> str:
    """ATT&CK technique coverage (Phase T, read-only, advisory): per-technique status
    (covered/weak/uncovered/model_only), supporting capabilities, and effectiveness; ranked, one
    technique, or filtered by tactic. `weak` includes single-provider (fragile) coverage.

    Args:
        technique_id: optional single technique id (e.g. "T1190"); omit for the list
        tactic_id: optional tactic filter (e.g. "TA0043"); ignored when technique_id is set
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_techniques(
        technique_id, tactic_id, _adversary_now(now)), indent=2)


@mcp.tool()
def attack_gaps(now: float = 0.0) -> str:
    """ATT&CK coverage gaps (Phase T, read-only, advisory): weakly-covered and uncovered in-scope
    techniques, weak tactics, Phase-Q campaign phases with thin technique coverage, and the Phase-S
    opportunities whose improvement lifts the most coverage. Model-only techniques are never gaps.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_gaps(_adversary_now(now)), indent=2)


@mcp.tool()
def attack_profiles(profile: str = "", now: float = 0.0) -> str:
    """Adversary profile support (Phase T, read-only, advisory): how well Hydra's coverage supports
    modelled adversary profiles (external recon / web-app / cloud / credential / supply-chain /
    surface-mapper); ranked, or a single profile. NON-executing — modelling is not emulation.

    Args:
        profile: optional single profile id (e.g. "cloud_attacker"); omit for all
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_profiles(profile, _adversary_now(now)), indent=2)


@mcp.tool()
def attack_skills(now: float = 0.0) -> str:
    """Skill → ATT&CK technique map (Phase T, read-only, advisory): which Phase-R skills contribute
    to which techniques/tactics, ranked by technique breadth.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_skills(_adversary_now(now)), indent=2)


@mcp.tool()
def attack_capabilities(limit: int = 25, now: float = 0.0) -> str:
    """Capability → ATT&CK technique map (Phase T, read-only, advisory): which capabilities provide
    the strongest technique coverage (effectiveness × technique breadth), ranked.

    Args:
        limit: max capabilities to return (default 25)
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_capabilities(
        max(1, limit), _adversary_now(now)), indent=2)


@mcp.tool()
def attack_health(now: float = 0.0) -> str:
    """Adversary-health (Phase T, read-only, advisory): a 0-100 score blending in-scope technique
    coverage, mean per-tactic coverage, and the effectiveness of covered techniques. Advisory; never
    alters confidence/promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_AdversaryIntelligence().attack_health(_adversary_now(now)), indent=2)


# ── Phase U — Threat Intelligence & Knowledge Fusion (derived, advisory, NON-executing) ──
# All eight tools are read-only/deterministic/advisory. They FUSE Hydra's existing knowledge layers
# (Federation N / Temporal O / Offensive P / Campaign Q / Skill R / Opportunity S / Adversary T) over
# a load-once ThreatContext (one OffensiveContext load threaded through Phase-T → S/Q/R, plus bounded
# guarded O and N signals). A Threat is keyed by an ATT&CK tactic; the fusion graph
# Threat→Campaign→Technique→Capability→Skill→Agent explains every edge. Store-free; it reasons over
# existing knowledge and never collects live intelligence, exploits, attacks, executes, or touches the
# canonical wiki / promotion.py / confidence.py. `now` is optional (<=0 = newest event).
def _threat_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def threat_summary(now: float = 0.0) -> str:
    """Threat intelligence overview (Phase U, read-only, advisory): threat-health, in-scope vs
    model-only threats, highest-risk threats, fusion-graph size, clusters, evolution, broadest
    adversary profiles, and bounded recommendations.

    Args:
        now: optional reference timestamp for determinism (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_summary(_threat_now(now)), indent=2)


@mcp.tool()
def threat_graph(threat_id: str = "", now: float = 0.0) -> str:
    """Threat fusion graph (Phase U, read-only, advisory): the unified
    Threat→Campaign→Technique→Capability→Skill→Agent graph; EVERY edge carries a `reason` (no hidden
    inference). Full graph, or one threat's subgraph.

    Args:
        threat_id: optional single threat / ATT&CK tactic id (e.g. "TA0043"); omit for the full graph
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_graph(threat_id, _threat_now(now)), indent=2)


@mcp.tool()
def threat_clusters(now: float = 0.0) -> str:
    """Threat clusters (Phase U, read-only, advisory): related threats grouped by shared backing
    capabilities (deterministic connected components), each with its shared capabilities/skills and an
    explainable reason.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_clusters(_threat_now(now)), indent=2)


@mcp.tool()
def threat_evolution(now: float = 0.0) -> str:
    """Threat evolution (Phase U, read-only, advisory): fuses Phase-O temporal momentum with Phase-T
    coverage to label threats rising / declining / stable and flag emerging patterns (weak coverage +
    emerging capabilities). Bounded; no prediction beyond deterministic signals.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_evolution(_threat_now(now)), indent=2)


@mcp.tool()
def threat_opportunities(now: float = 0.0) -> str:
    """Threat ↔ opportunity fusion (Phase U, read-only, advisory): which threats are most exposed
    (weak coverage / capability gaps) and which Phase-S opportunities would close the most risk.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_opportunities(_threat_now(now)), indent=2)


@mcp.tool()
def threat_skills(now: float = 0.0) -> str:
    """Threat ↔ skill fusion (Phase U, read-only, advisory): which skills matter most (touch the most
    threats), which are underrepresented, and which skill gaps create the largest threat exposure.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_skills(_threat_now(now)), indent=2)


@mcp.tool()
def threat_campaigns(now: float = 0.0) -> str:
    """Threat ↔ campaign fusion (Phase U, read-only, advisory): which campaign phases are best
    covered, which paths are weakest, and which stages rely on fragile (single-provider) capability
    coverage.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_campaigns(_threat_now(now)), indent=2)


@mcp.tool()
def threat_health(now: float = 0.0) -> str:
    """Threat-health (Phase U, read-only, advisory): a 0-100 score fusing coverage, redundancy /
    resilience, diversity, opportunity gaps, temporal decay, and federation consensus. Fully
    explainable; advisory — never alters confidence/promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_ThreatIntelligence().threat_health(_threat_now(now)), indent=2)


# ── Bug-Bounty Authorization Gate (DENY-BY-DEFAULT enforcement) ──
# The safety keystone for moving from advisory modelling toward actual vulnerability validation /
# exploitation: an active action is permitted ONLY against a target proven in-scope for a registered
# bug bounty program (published authorization). With no covering program, every active action is
# DENIED. Absolute prohibitions (DoS / destructive / data-exfil / social-engineering) are never
# allowed, even in-scope; exploitation is PoC-only. The registry is operator-owned
# (data/authorized_programs.json; HYDRA_AUTHORIZED_PROGRAMS to override).
@mcp.tool()
def register_bounty_program(program: str, platform: str, in_scope: str,
                            out_of_scope: str = "", url: str = "") -> str:
    """Register a bug bounty program's published scope = authorization to test its in-scope assets.

    The platform will then permit active/exploitation actions ONLY against these in-scope assets
    (deny-by-default for everything else). In production, prefer sourcing scope live from the program
    (HackerOne/Bugcrowd/etc.) rather than hand-entering it.

    Args:
        program: program handle/name (e.g. "acme")
        platform: bug bounty platform (hackerone | bugcrowd | intigriti | yeswehack | ... | custom)
        in_scope: comma-separated in-scope assets (e.g. "*.acme.com, app.acme.io")
        out_of_scope: comma-separated explicitly out-of-scope assets (optional)
        url: program URL (optional, for provenance)
    """
    ins = [a.strip() for a in in_scope.split(",") if a.strip()]
    oos = [a.strip() for a in out_of_scope.split(",") if a.strip()]
    try:
        bp = _AuthGate().register_program(program, platform, ins, oos, url)
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "registered": bp.to_dict()}, indent=2)


@mcp.tool()
def authorize_target(target: str, action: str = "exploitation") -> str:
    """Deny-by-default authorization check: may the platform take `action` against `target`?

    Returns ALLOW only if the target is in-scope for a registered bug bounty program and the action is
    not an absolute prohibition (exploitation is authorized PoC-only). Call this immediately before any
    active action; treat a non-authorized result as a hard stop.

    Args:
        target: the target url/host (e.g. "https://api.acme.com/v1")
        action: passive_recon | active_recon | vulnerability_scan | exploitation | data_access
    """
    return json.dumps(_AuthGate().authorize(target, action).to_dict(), indent=2)


# ── Attack Section (executable, authorization-gated, PoC-only) ──
# Every tool that names a TARGET is gated by the bug-bounty authorization gate (deny-by-default); the
# pure payload-library tools do not name a target. All payloads are detection / proof-of-concept grade
# (no exfiltration / destruction / DoS). `attack_plan` never sends traffic via MCP — it returns a
# gated, dry-run plan; actual execution requires an explicitly injected executor in code.
@mcp.tool()
def attack_plan(target: str, vuln_class: str, context: str = "any") -> str:
    """Authorization-gated attack PLAN (Phase: attack section): deny-by-default → ATT&CK technique →
    context-aware PoC payloads → candidate exploit chains. Never sends traffic (dry-run). A
    non-authorized target returns `authorized: false` and an empty plan.

    Args:
        target: target url/host (must be in-scope for a registered bug bounty program)
        vuln_class: xss | sqli | ssti | ssrf | xxe | crlf | path_traversal | cmdi | open_redirect | lfi
        context: html_body | html_attr | js_string | url | sql | header | path | any
    """
    return json.dumps(_AttackWorkflow().plan(target, vuln_class, context), indent=2)


@mcp.tool()
def waf_bypass(url: str, method: str = "GET") -> str:
    """Automated 403/WAF bypass generator (attack section): the systematic path/method/header/host/
    encoding permutation set for a URL. Authorization-gated — a non-authorized target is denied
    (deny-by-default) and no attempts are returned.

    Args:
        url: the 403/forbidden URL to attempt bypasses for (must be bug-bounty in-scope)
        method: base HTTP method (default GET)
    """
    decision = _AuthGate().authorize(url, "vulnerability_scan")
    if not decision.authorized:
        return json.dumps({"authorized": False, "reason": decision.reason, "attempts": []}, indent=2)
    out = _Bypass403().report(url, method)
    out["authorized"] = True
    return json.dumps(out, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  POST-EXPLOITATION & IMPACT  (gated, authorized-engagement, PoC-only)
# ══════════════════════════════════════════════════════════════════════════════
# Active internal / Active-Directory tradecraft for DEMONSTRATING IMPACT once an
# authorized foothold exists (privilege escalation, lateral movement, AD enumeration,
# credential-store access). Every target-naming tool is gated by the SAME deny-by-default
# authorization gate as the attack section — an out-of-scope target is a HARD STOP.
# PoC-only: enumerate and PROVE access; never exfiltrate bulk data, never destroy, never
# persist. Excluded by policy (CLAUDE.md non-negotiables): DoS, ransomware/destructive,
# data-exfiltration, social-engineering/phishing, detection-evasion / AV-EDR-bypass, and
# persistent C2 — none of which belong in an impact PoC.

def _reject_flaglike(*vals) -> Optional[dict]:
    """Reject any argument that looks like a CLI flag (leading '-'). Args go to argv
    (shell=False) so there is no shell injection, but a '-'-prefixed value could be
    mis-parsed by the tool as an option — block that."""
    for v in vals:
        s = str(v or "")
        if s.startswith("-"):
            return _err(f"Rejected argument '{v}': leading '-' looks like a flag, not a value")
    return None


def _gate_or_reject(target: str, action: str = "exploitation"):
    """Validate `target` then run the deny-by-default authorization gate.
    Returns (decision, None) when ALLOWED, or (None, error_json_str) when rejected."""
    err = _validate_host(target, allow_cidr=True)
    if err:
        return None, json.dumps(err, indent=2)
    decision = _AuthGate().authorize(target, action)
    if not decision.authorized:
        return None, json.dumps({
            "authorized": False,
            "reason": decision.reason,
            "note": ("Out-of-scope for any registered bug-bounty program — hard stop. "
                     "Register the engagement scope (load_bounty_scope) before active testing."),
        }, indent=2)
    return decision, None


def _localfile_or_reject(path: str) -> Optional[dict]:
    """Reject flag-like or non-existent local file paths (for offline tools)."""
    e = _reject_flaglike(path)
    if e:
        return e
    if not path or not os.path.isfile(path):
        return _err(f"File not found: '{path}'")
    return None


@mcp.tool()
def enum4linux_scan(target: str, timeout: int = 300) -> str:
    """Gated SMB / Active-Directory enumeration via enum4linux-ng (shares, users, groups,
    password policy, OS, RID cycling). Authorized-engagement IMPACT tool — read-only
    enumeration; deny-by-default (out-of-scope target = hard stop).

    Args:
        target: in-scope host/IP of an SMB/AD server
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(target, "vulnerability_scan")
    if rej:
        return rej
    return json.dumps(_run(["enum4linux-ng", "-A", target], timeout=timeout), indent=2)


@mcp.tool()
def smbmap_scan(target: str, username: str = "", password: str = "", domain: str = "",
                timeout: int = 180) -> str:
    """Gated SMB share enumeration + per-share read/write permissions via smbmap (anonymous
    or authenticated). IMPACT tool: shows which shares an identity can reach. Deny-by-default.

    Args:
        target: in-scope host/IP
        username/password/domain: optional credentials (blank = anonymous/guest)
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(target, "vulnerability_scan")
    if rej:
        return rej
    fl = _reject_flaglike(username, password, domain)
    if fl:
        return json.dumps(fl, indent=2)
    cmd = ["smbmap", "-H", target]
    if username:
        cmd += ["-u", username, "-p", password]
    else:
        cmd += ["-u", "guest", "-p", ""]
    if domain:
        cmd += ["-d", domain]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def ldapsearch_query(target: str, base_dn: str, ldap_filter: str = "(objectClass=*)",
                     username: str = "", password: str = "", attributes: str = "",
                     timeout: int = 120) -> str:
    """Gated LDAP / AD directory query via ldapsearch (anonymous or simple-bind). IMPACT tool
    for enumerating AD objects (users, groups, SPNs, GPOs). Deny-by-default.

    Args:
        target: in-scope LDAP/AD host/IP
        base_dn: search base, e.g. "DC=corp,DC=local"
        ldap_filter: LDAP filter (default all objects)
        username/password: optional bind DN + password
        attributes: optional space-separated attribute list to return
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(target, "vulnerability_scan")
    if rej:
        return rej
    fl = _reject_flaglike(base_dn, ldap_filter, username, attributes)
    if fl:
        return json.dumps(fl, indent=2)
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base_dn]
    if username:
        cmd += ["-D", username, "-w", password]
    cmd.append(ldap_filter)
    if attributes:
        cmd += [a for a in attributes.split() if not a.startswith("-")]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "",
                 domain: str = "", nt_hash: str = "", shares: bool = False,
                 command: str = "", timeout: int = 240) -> str:
    """Gated lateral-movement / AD assessment via netexec (nxc). Authenticates across a
    protocol, optionally enumerates shares or runs a single PoC command for impact proof.
    Deny-by-default; PoC-only — use BENIGN proof commands (whoami / id / hostname), never
    destructive or data-harvesting commands.

    Args:
        target: in-scope host/IP or CIDR
        protocol: smb | ldap | winrm | mssql | ssh | rdp | wmi | ftp | nfs | vnc
        username/password/domain: credentials
        nt_hash: NT hash for pass-the-hash (instead of password)
        shares: enumerate accessible shares (smb)
        command: a single benign PoC command to prove code-exec (winrm/mssql/ssh/wmi)
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(target, "exploitation")
    if rej:
        return rej
    proto = protocol.lower()
    if proto not in {"smb", "ldap", "winrm", "mssql", "ssh", "rdp", "wmi", "ftp", "nfs", "vnc"}:
        return json.dumps(_err(f"Unknown protocol '{protocol}'"), indent=2)
    fl = _reject_flaglike(username, password, domain, nt_hash, command)
    if fl:
        return json.dumps(fl, indent=2)
    cmd = ["nxc", proto, target]
    if username:
        cmd += ["-u", username]
    if nt_hash:
        cmd += ["-H", nt_hash]
    elif password:
        cmd += ["-p", password]
    if domain:
        cmd += ["-d", domain]
    if shares:
        cmd.append("--shares")
    if command:
        cmd += ["-x", command]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def secretsdump_run(target: str, username: str, password: str = "", domain: str = "",
                    nt_hashes: str = "", just_dc_user: str = "", timeout: int = 300) -> str:
    """Gated credential-store access via impacket-secretsdump (SAM/LSA/cached creds, or NTDS
    via DRSUAPI). IMPACT proof that an identity can reach credential material. Deny-by-default,
    PoC-only — prove the access; do NOT bulk-harvest/exfiltrate beyond the minimal proof
    (use `just_dc_user` to dump a single account rather than the whole directory).

    Args:
        target: in-scope host/IP (DC for NTDS, or a member for SAM/LSA)
        username: account name
        password: account password (or use nt_hashes)
        domain: AD domain (optional)
        nt_hashes: "LM:NT" for pass-the-hash auth instead of password
        just_dc_user: limit a DCSync to a single account (PoC scoping) e.g. "krbtgt"
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(target, "exploitation")
    if rej:
        return rej
    fl = _reject_flaglike(username, password, domain, nt_hashes, just_dc_user)
    if fl:
        return json.dumps(fl, indent=2)
    auth = f"{domain}/{username}" if domain else username
    if password:
        auth = f"{auth}:{password}"
    cmd = ["impacket-secretsdump", f"{auth}@{target}"]
    if nt_hashes:
        cmd += ["-hashes", nt_hashes]
    if just_dc_user:
        cmd += ["-just-dc-user", just_dc_user]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def bloodhound_collect(domain: str, username: str, password: str, dc_ip: str,
                       collection: str = "Default", timeout: int = 600) -> str:
    """Gated AD attack-path collection via bloodhound-python (SharpHound for Python). Produces
    a graph dataset (zipped JSON) for offline attack-path analysis to demonstrate escalation
    paths. Deny-by-default (gated on the DC IP); read-only LDAP/SMB collection.

    Args:
        domain: AD domain (e.g. "corp.local")
        username/password: domain credentials
        dc_ip: in-scope domain-controller IP (gated)
        collection: Default | All | DCOnly | Group | LocalAdmin | Session | ACL | Trusts | Container
        timeout: execution timeout in seconds
    """
    _decision, rej = _gate_or_reject(dc_ip, "vulnerability_scan")
    if rej:
        return rej
    if collection not in {"Default", "All", "DCOnly", "Group", "LocalAdmin", "Session",
                          "LoggedOn", "ACL", "Trusts", "Container", "RDP", "DCOM", "PSRemote"}:
        return json.dumps(_err(f"Unknown collection method '{collection}'"), indent=2)
    fl = _reject_flaglike(domain, username, password)
    if fl:
        return json.dumps(fl, indent=2)
    cmd = ["bloodhound-python", "-d", domain, "-u", username, "-p", password,
           "-ns", dc_ip, "-c", collection, "--zip"]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def hashcat_crack(hash_file: str, hash_mode: int,
                  wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  timeout: int = 600) -> str:
    """Offline hash cracking via hashcat (LOCAL files only; names no target, NOT gated). For
    cracking credential hashes captured during an authorized engagement to demonstrate impact.

    Args:
        hash_file: path to a file of hashes (must exist locally)
        hash_mode: hashcat -m mode (e.g. 1000=NTLM, 5600=NetNTLMv2, 1800=sha512crypt, 22000=WPA)
        wordlist: wordlist path
        timeout: execution timeout in seconds
    """
    e = _localfile_or_reject(hash_file) or _localfile_or_reject(wordlist)
    if e:
        return json.dumps(e, indent=2)
    try:
        mode = str(int(hash_mode))
    except (TypeError, ValueError):
        return json.dumps(_err(f"hash_mode must be an integer, got '{hash_mode}'"), indent=2)
    cmd = ["hashcat", "-m", mode, "-a", "0", hash_file, wordlist,
           "--quiet", "--potfile-disable", "--force"]
    return json.dumps(_run(cmd, timeout=timeout), indent=2)


@mcp.tool()
def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
               fmt: str = "", timeout: int = 600) -> str:
    """Offline hash cracking via John the Ripper (LOCAL files only; names no target, NOT gated).
    Cracks then returns the recovered plaintext (john --show) for authorized impact proof.

    Args:
        hash_file: path to a file of hashes (must exist locally)
        wordlist: wordlist path
        fmt: optional john --format (e.g. "nt", "sha512crypt", "netntlmv2")
        timeout: execution timeout in seconds
    """
    e = _localfile_or_reject(hash_file) or _localfile_or_reject(wordlist)
    if e:
        return json.dumps(e, indent=2)
    fl = _reject_flaglike(fmt)
    if fl:
        return json.dumps(fl, indent=2)
    crack = ["john", f"--wordlist={wordlist}", hash_file]
    show = ["john", "--show", hash_file]
    if fmt:
        crack.append(f"--format={fmt}")
        show.append(f"--format={fmt}")
    _run(crack, timeout=timeout)
    return json.dumps(_run(show, timeout=60), indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  GENERAL EXECUTION — one shell, runs all of Kali (curl-first)
# ══════════════════════════════════════════════════════════════════════════════
# A single flexible shell tool for the long tail of Kali utilities that don't
# have a dedicated typed wrapper. Mirrors PentesterFlow's `shell`: the operator's
# harness still prompts for approval on each call (HITL), and a catastrophic-
# command denylist is a HARD BLOCK that fires regardless of operator/YOLO mode —
# defense-in-depth against foot-guns on the operator's OWN box, not a security
# boundary against a determined model. Output is head/tail truncated by _run.
# The four absolute prohibitions (DoS / destructive / data-exfil / social-eng)
# remain platform policy and are enforced at the authorization layer.

# Catastrophic-command denylist (adapted from PentesterFlow DENY_PATTERNS): rm -rf
# of root/top-level, fork bombs, disk wipes, mass deletes, power state changes.
_SHELL_DENY_PATTERNS = [
    _re.compile(r"\brm\b(?=[^|;&\n]*\s-{1,2}[a-z-]*r)(?=[^|;&\n]*\s-{1,2}[a-z-]*f)"
                r"[^|;&\n]*\s/[^/\s]*/?(?:\s|$)", _re.I),
    _re.compile(r"\brm\b(?=[^|;&\n]*\s-{1,2}[a-z-]*r)(?=[^|;&\n]*\s-{1,2}[a-z-]*f)"
                r"[^|;&\n]*\s[\"']/[^/\"'\s]*/?[\"'](?:\s|$)", _re.I),
    _re.compile(r":\(\)\s*\{\s*:\|:&\s*\}", _re.I),          # fork bomb
    _re.compile(r"\bmkfs\b", _re.I),
    _re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/", _re.I),
    _re.compile(r">\s*/dev/sd[a-z]", _re.I),
    _re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b", _re.I),
    _re.compile(r"\bfind\b[^|;&\n]*\s-delete\b", _re.I),
    _re.compile(r"\bfind\b[^|;&\n]*\s-exec\s+rm\b", _re.I),
]


@mcp.tool()
def shell_exec(command: str, timeout: int = 300, shell: str = "bash") -> str:
    """Run a shell command for HTTP testing / file inspection / one-liners — the
    flexible escape hatch for any Kali tool without a dedicated wrapper. Default to
    `curl` for HTTP work; reach for scanners (ffuf/nuclei/sqlmap/…) only when asked.

    HITL: the harness prompts for approval on each call. A catastrophic-command
    denylist (rm -rf /, fork bomb, mkfs, dd of=/dev/*, shutdown, find -delete) is a
    HARD BLOCK regardless of operator/YOLO mode. The operator is responsible for
    keeping commands in declared engagement scope; the four absolute prohibitions
    (DoS / destructive / data-exfil / social-engineering) are never permitted.

    Args:
        command: the shell command (pipes, &&, etc. supported)
        timeout: execution timeout in seconds (max 1800)
        shell: "bash" (default) or "sh"
    """
    cmd_str = (command or "").strip()
    if not cmd_str:
        return json.dumps(_err("command is required"), indent=2)
    for rx in _SHELL_DENY_PATTERNS:
        if rx.search(cmd_str):
            return json.dumps(_err(
                f"command blocked by catastrophic-command denylist (matched /{rx.pattern}/). "
                "This guard fires even in operator/YOLO mode."), indent=2)
    interpreter = "/bin/bash" if shell != "sh" else "/bin/sh"
    timeout = max(1, min(int(timeout) if str(timeout).lstrip("-").isdigit() else 300, 1800))
    result = _run([interpreter, "-c", cmd_str], timeout=timeout)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  BROWSER & BURP CAPTURE
# ══════════════════════════════════════════════════════════════════════════════
# Burp-bridge capture query/ingest (the in-process CaptureStore the optional
# `start_bridge` localhost server also writes to) + a Playwright browser crawler.
# The capture store is bounded + control-byte-scrubbed (see hydra/burp). The
# browser crawler renders JS to surface SPA endpoints/tokens/cookies — active
# recon, so it is authorization-gated (deny-by-default).


@mcp.tool()
def burp_status() -> str:
    """Capture-store status: how many requests/endpoints are buffered + the bounds.
    Feed traffic in via the Burp companion (start_bridge) or `burp_ingest`."""
    from hydra.burp import STORE
    return json.dumps(STORE.stats(), indent=2)


@mcp.tool()
def burp_requests(limit: int = 50) -> str:
    """List recently-captured requests (newest first) from the capture store.

    Args:
        limit: max requests to return
    """
    from hydra.burp import STORE
    lim = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 50, 500))
    return json.dumps({"requests": STORE.requests(limit=lim)}, indent=2)


@mcp.tool()
def burp_endpoints(limit: int = 100) -> str:
    """List distinct captured endpoints with their accumulated parameter names.

    Args:
        limit: max endpoints to return
    """
    from hydra.burp import STORE
    lim = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 100, 1000))
    return json.dumps({"endpoints": STORE.endpoints(limit=lim)}, indent=2)


@mcp.tool()
def burp_ingest(method: str, url: str, status: int = 0, raw: str = "",
                note: str = "", params: str = "") -> str:
    """Push a captured request (e.g. pasted from Burp) into the capture store for
    later querying/replay. Text is control-byte scrubbed and bounded on insert.

    Args:
        method: HTTP method
        url: full request URL
        status: response status code (optional)
        raw: full raw request material for evidence/replay (optional)
        note: free-text note (optional)
        params: comma-separated parameter names (optional)
    """
    from hydra.burp import STORE
    plist = [p.strip() for p in params.split(",") if p.strip()] if params else []
    cr = STORE.add(method=method, url=url, status=status, raw=raw, note=note, params=plist)
    return json.dumps({"stored": cr.to_dict()}, indent=2)


@mcp.tool()
def burp_ingest_sitemap(items_json: str) -> str:
    """Site-map import: bulk-ingest a JSON array of request records
    [{method,url,host,status,raw,note,params[]}] (scrubbed + bounded per item).

    Args:
        items_json: JSON array of request records
    """
    from hydra.burp import STORE
    try:
        items = json.loads(items_json)
        if not isinstance(items, list):
            raise ValueError("expected a JSON array")
    except (json.JSONDecodeError, ValueError) as e:
        return json.dumps(_err(f"invalid items_json: {e}"), indent=2)
    return json.dumps(STORE.add_bulk(items), indent=2)


@mcp.tool()
def burp_issue(action: str = "add", name: str = "", url: str = "", severity: str = "info",
               detail: str = "", request: str = "", response: str = "", confidence: str = "",
               issue_id: str = "", engagement_id: str = "", limit: int = 50) -> str:
    """Burp Scanner issue integration. `add` records a scrubbed issue; `list` lists
    issue metadata; `to_finding` promotes an issue into a DRAFT finding (round-trip)
    carrying its request/response as evidence.

    Args:
        action: add | list | to_finding
        name/url/severity/detail/request/response/confidence: issue fields (for add)
        issue_id: target issue (for to_finding)
        engagement_id: engagement for the created draft finding (for to_finding)
        limit: max issues (for list)
    """
    from hydra.burp import STORE
    if action == "add":
        if not name or not url:
            return json.dumps(_err("add requires name and url"), indent=2)
        return json.dumps({"issue": {k: v for k, v in
                          STORE.add_issue(name, url, severity, detail=detail, request=request,
                                          response=response, confidence=confidence).items()
                          if k not in ("request", "response")}}, indent=2)
    if action == "list":
        lim = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 50, 500))
        return json.dumps({"issues": STORE.issues(limit=lim)}, indent=2)
    if action == "to_finding":
        issue = STORE.get_issue(issue_id)
        if not issue:
            return json.dumps(_err(f"unknown issue '{issue_id}'"), indent=2)
        if not engagement_id:
            return json.dumps(_err("to_finding requires engagement_id"), indent=2)
        fs = _findings()
        fid = fs.create(engagement_id, issue["name"], vuln_class=issue["name"].lower().split()[0],
                        severity=issue["severity"], endpoint=issue["url"], impact=issue["detail"])
        if issue.get("request"):
            fs.add_evidence(fid, "request", issue["request"])
        if issue.get("response"):
            fs.add_evidence(fid, "response", issue["response"])
        return json.dumps({"finding_id": fid, "state": "draft",
                           "evidence": ["request", "response"]}, indent=2)
    return json.dumps(_err(f"unknown action '{action}' (add|list|to_finding)"), indent=2)


@mcp.tool()
def burp_repeater(method: str, url: str) -> str:
    """Repeater: fetch the stored RAW request material for a captured (method, url)
    so it can be replayed/edited. Returns the raw text or an error if not captured.

    Args:
        method: HTTP method
        url: full request URL
    """
    from hydra.burp import STORE
    raw = STORE.get_raw(method, url)
    if raw is None:
        return json.dumps(_err(f"no captured raw request for {method} {url}"), indent=2)
    return json.dumps({"method": method.upper(), "url": url, "raw": raw}, indent=2)


@mcp.tool()
def burp_timeline(limit: int = 100) -> str:
    """Session recording: the ordered timeline of captured requests + scanner issues
    (a replayable record of the engagement's traffic).

    Args:
        limit: max timeline entries (most recent)
    """
    from hydra.burp import STORE
    lim = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 100, 1000))
    return json.dumps({"timeline": STORE.timeline(limit=lim)}, indent=2)


@mcp.tool()
def browser_crawl(url: str, depth: int = 2, headless: bool = True, max_pages: int = 25) -> str:
    """Gated headless-browser crawl (Playwright): renders JS to surface SPA
    endpoints, forms, tokens/JWTs, cookies, storage secrets, and WebSocket URLs.
    Active recon — authorization-gated (deny-by-default). Requires Playwright
    (`pip install playwright && playwright install chromium`); degrades to a clear
    message if unavailable.

    Args:
        url: in-scope target URL to crawl
        depth: crawl depth (1-5)
        headless: run the browser headless
        max_pages: max pages to visit (bounded)
    """
    import asyncio as _asyncio
    err = _validate_url(url)
    if err:
        return json.dumps(err, indent=2)
    decision = _AuthGate().authorize(url, "active_recon")
    if not decision.authorized:
        return json.dumps({"authorized": False, "reason": decision.reason,
                           "note": "Out-of-scope — register the engagement scope first."}, indent=2)
    depth = max(1, min(int(depth) if str(depth).lstrip("-").isdigit() else 2, 5))
    max_pages = max(1, min(int(max_pages) if str(max_pages).lstrip("-").isdigit() else 25, 200))

    async def _go():
        from hydra.browser import BrowserIntelligenceEngine
        eng = BrowserIntelligenceEngine(headless=headless, max_pages=max_pages)
        await eng.initialize()
        try:
            return await eng.crawl(url, depth=depth)
        finally:
            await eng.close()

    try:
        session = _asyncio.run(_go())
    except Exception as e:  # Playwright missing / launch failure → clear, non-fatal
        return json.dumps(_err(f"browser crawl unavailable: {e}. "
                               "Install: pip install playwright && playwright install chromium"),
                          indent=2)
    out = {
        "authorized": True,
        "target": session.target,
        "pages_visited": session.pages_visited,
        "endpoints": sorted(session.endpoints),
        "tokens_found": session.tokens_found,
        "cookies": session.cookies_collected,
        "screenshots": session.screenshots,
        "findings": [vars(f) for f in session.findings],
        "duration_seconds": round(session.duration, 2),
    }
    return json.dumps(out, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  FINDINGS LIFECYCLE & COVERAGE  (architecture spec Parts 4 & 5)
# ══════════════════════════════════════════════════════════════════════════════
# Production findings state machine (draft→validated→confirmed→reported→remediated)
# with evidence-gated confirm (no confirm without request+response evidence), CVSS
# scoring, and a coverage matrix with the /next engine. SQLite under ./findings/.

_FINDINGS_STORE = None
_COVERAGE_STORE = None


def _findings():
    global _FINDINGS_STORE
    if _FINDINGS_STORE is None:
        from hydra.findings import FindingsStore
        _FINDINGS_STORE = FindingsStore()
    return _FINDINGS_STORE


def _coverage():
    global _COVERAGE_STORE
    if _COVERAGE_STORE is None:
        from hydra.coverage import CoverageStore
        _COVERAGE_STORE = CoverageStore()
    return _COVERAGE_STORE


@mcp.tool()
def finding_create(engagement_id: str, title: str, vuln_class: str = "", severity: str = "info",
                   asset: str = "", endpoint: str = "", method: str = "GET", parameter: str = "",
                   payload: str = "", impact: str = "", remediation: str = "", cwe: str = "",
                   owasp: str = "") -> str:
    """Create a DRAFT finding (idempotent by root cause: same vuln_class + normalized
    endpoint returns the existing id). Promote it later via finding_transition.

    Args:
        engagement_id: engagement/workspace id
        title: short finding title
        vuln_class: idor|sqli|xss|ssrf|... (used for dedup + coverage)
        severity: info|low|medium|high|critical (or set via finding_score CVSS)
        asset/endpoint/method/parameter/payload: location + trigger
        impact/remediation: narrative
        cwe: e.g. CWE-89   owasp: e.g. A01:2021
    """
    fid = _findings().create(engagement_id, title, vuln_class=vuln_class, severity=severity,
                             asset=asset, endpoint=endpoint, method=method, parameter=parameter,
                             payload=payload, impact=impact, remediation=remediation, cwe=cwe,
                             owasp=owasp)
    return json.dumps({"id": fid, "state": "draft"}, indent=2)


@mcp.tool()
def finding_add_evidence(finding_id: str, kind: str, content: str) -> str:
    """Attach evidence to a finding (content is secret-redacted + sha256'd on store).
    Confirm requires BOTH a 'request' and a 'response' evidence row.

    Args:
        finding_id: target finding
        kind: request | response | screenshot | tool_output | curl
        content: the evidence text
    """
    try:
        return json.dumps(_findings().add_evidence(finding_id, kind, content), indent=2)
    except KeyError as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def finding_transition(finding_id: str, to_state: str) -> str:
    """Move a finding through its lifecycle: draft→validated→confirmed→reported→
    remediated (reject from any pre-report state). Confirm is EVIDENCE-GATED.

    Args:
        finding_id: target finding
        to_state: validated | confirmed | rejected | reported | remediated
    """
    from hydra.findings import EvidenceGateError, TransitionError
    try:
        return json.dumps(_findings().transition(finding_id, to_state), indent=2)
    except (TransitionError, EvidenceGateError, KeyError) as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def finding_score(finding_id: str, cvss_vector: str = "", cvss_score: float = 0.0) -> str:
    """Set a finding's CVSS vector + base score; severity is derived from the band.

    Args:
        finding_id: target finding
        cvss_vector: e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        cvss_score: base score 0.0-10.0
    """
    return json.dumps(_findings().score(finding_id, cvss_vector, cvss_score), indent=2)


@mcp.tool()
def finding_list(engagement_id: str, state: str = "") -> str:
    """List findings for an engagement (optionally filtered by state) + summary + dedup clusters.

    Args:
        engagement_id: engagement/workspace id
        state: optional state filter
    """
    fs = _findings()
    return json.dumps({"findings": fs.list(engagement_id, state),
                       "summary": fs.summary(engagement_id),
                       "correlation": fs.correlate(engagement_id)}, indent=2)


@mcp.tool()
def coverage_record(engagement_id: str, endpoint: str, vuln_class: str, method: str = "GET",
                    parameter: str = "", asset: str = "", auth_area: str = "",
                    status: str = "untested", evidence_finding_id: str = "") -> str:
    """Record/update a coverage tuple (asset×endpoint×method×param×vuln_class).

    Args:
        engagement_id: engagement id
        endpoint/method/parameter/asset/auth_area: the tested surface
        vuln_class: vuln class tested
        status: untested|passed|failed|skipped|waf-blocked
        evidence_finding_id: link to a finding if one resulted
    """
    return json.dumps(_coverage().record(engagement_id, endpoint, vuln_class, method=method,
                      parameter=parameter, asset=asset, auth_area=auth_area, status=status,
                      evidence_finding_id=evidence_finding_id), indent=2)


@mcp.tool()
def coverage_summary(engagement_id: str) -> str:
    """Coverage / attack-surface / risk scores for an engagement (risk folds in open
    confirmed-finding severities)."""
    fs = _findings()
    open_states = ("confirmed", "validated", "reported")
    sevs = [f["severity"] for st in open_states for f in fs.list(engagement_id, st)]
    return json.dumps(_coverage().summary(engagement_id, open_finding_severities=sevs), indent=2)


@mcp.tool()
def coverage_next(engagement_id: str, limit: int = 10) -> str:
    """The /next engine: highest-value UNTESTED tuples (auth-area × high-impact class first).

    Args:
        engagement_id: engagement id
        limit: max suggestions
    """
    lim = max(1, min(int(limit) if str(limit).lstrip("-").isdigit() else 10, 100))
    return json.dumps({"next": _coverage().next(engagement_id, limit=lim)}, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  4-TIER CONTINUOUS LEARNING  (architecture spec Part 2)
# ══════════════════════════════════════════════════════════════════════════════
# project → personal → cross → org lessons. WRITE is a poison gate (TN-1: steering/
# exfil text quarantined, never retrieved); RETRIEVAL fences results as untrusted
# data (TN-2); promotion is approval-gated (org needs >=2 confirmations). SQLite
# under ./.thenothing/learning/.

_LEARN_STORE = None


def _learn():
    global _LEARN_STORE
    if _LEARN_STORE is None:
        from hydra.learning_tiers import LearningTiersStore
        _LEARN_STORE = LearningTiersStore()
    return _LEARN_STORE


@mcp.tool()
def learn_record(tier: str, title: str, category: str, lesson: str, triggers: str = "",
                 technologies: str = "", source_class: str = "manual", host: str = "",
                 engagement_id: str = "") -> str:
    """Record a cross-session lesson into a learning tier. The write path is a
    poison gate: target-derived steering/exfil text is QUARANTINED (stored for
    audit, never retrieved). Secrets are redacted; the host is stored hashed.

    Args:
        tier: project | personal | cross | org
        title: short lesson title
        category: e.g. recon-gap | auth-bypass | waf
        lesson: the reusable lesson text
        triggers/technologies: comma-separated match hints
        source_class: confirmed_finding|verification|manual|recon|tool_output (sets trust prior)
        host: target host (stored only as a hash — provenance without leakage)
        engagement_id: originating engagement
    """
    trg = [t.strip() for t in triggers.split(",") if t.strip()]
    tec = [t.strip() for t in technologies.split(",") if t.strip()]
    try:
        return json.dumps(_learn().record(tier, title, category, lesson, triggers=trg,
                          technologies=tec, source_class=source_class, host=host,
                          engagement_id=engagement_id), indent=2)
    except ValueError as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def learn_search(query: str, tier: str = "all", k: int = 5) -> str:
    """Recall lessons (fenced as untrusted data) by token-overlap × recency × trust.
    Only ACTIVE (non-quarantined) lessons are returned.

    Args:
        query: free-text query
        tier: project|personal|cross|org|all
        k: max results
    """
    lim = max(1, min(int(k) if str(k).lstrip("-").isdigit() else 5, 25))
    return json.dumps({"results": _learn().search(query, tier=tier, k=lim)}, indent=2)


@mcp.tool()
def learn_quarantined() -> str:
    """List quarantined lessons (flagged by the TN-1 poison gate) for human review."""
    return json.dumps({"quarantined": _learn().quarantined()}, indent=2)


@mcp.tool()
def learn_review(lesson_id: str, action: str) -> str:
    """Govern a lesson: approve (release a quarantined lesson), reject (drop it),
    or confirm (raise trust; 2 confirmations enable org-tier promotion).

    Args:
        lesson_id: the lesson id
        action: approve | reject | confirm
    """
    st = _learn()
    fn = {"approve": st.approve, "reject": st.reject, "confirm": st.confirm}.get(action)
    if not fn:
        return json.dumps(_err(f"unknown action '{action}' (approve|reject|confirm)"), indent=2)
    return json.dumps(fn(lesson_id), indent=2)


@mcp.tool()
def learn_promote(lesson_id: str, to_tier: str) -> str:
    """Promote a lesson toward a broader tier (project→personal→cross→org). Must
    broaden; can't promote a quarantined lesson; org requires >=2 confirmations.

    Args:
        lesson_id: the lesson id
        to_tier: personal | cross | org
    """
    try:
        return json.dumps(_learn().promote(lesson_id, to_tier), indent=2)
    except (ValueError, KeyError) as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def learn_stats() -> str:
    """Learning-store stats: active lessons per tier + quarantined count."""
    return json.dumps(_learn().stats(), indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNED SKILLS 2.0  (architecture spec Part 3)
# ══════════════════════════════════════════════════════════════════════════════
# Multi-format (MD/YAML/JSON) skill manifests with SemVer dependencies, discovery-
# order overrides (+ shadow warning when a local skill shadows a SIGNED builtin),
# detached HMAC signatures, and trust-gated install. Skills are DATA — never
# executed here. A process-wide registry the tools share.

_SKILL_REGISTRY = None


def _skillreg():
    global _SKILL_REGISTRY
    if _SKILL_REGISTRY is None:
        from hydra.skill_registry import SignedSkillRegistry
        _SKILL_REGISTRY = SignedSkillRegistry()
    return _SKILL_REGISTRY


@mcp.tool()
def skill_parse(text: str, fmt: str = "md", source: str = "inline") -> str:
    """Parse a skill manifest (Markdown frontmatter / YAML / JSON) into the canonical
    form (id, name, version, allowed_tools, requires, triggers) without registering it.

    Args:
        text: the skill source
        fmt: md | yaml | json
        source: builtin | marketplace | personal | project | extra | inline
    """
    from hydra.skill_registry import parse_manifest
    try:
        m = parse_manifest(text, fmt, source=source)
    except Exception as e:
        return json.dumps(_err(f"parse failed: {e}"), indent=2)
    return json.dumps(m.to_dict(), indent=2)


@mcp.tool()
def skill_register(text: str, fmt: str = "md", source: str = "inline") -> str:
    """Parse + register a skill manifest in the signed registry. Higher-precedence
    sources override lower ones on id collision; a local skill shadowing a SIGNED
    builtin emits a warning. Returns the action + any warnings.

    Args:
        text: the skill source
        fmt: md | yaml | json
        source: builtin | marketplace | personal | project | extra | inline
    """
    from hydra.skill_registry import parse_manifest
    reg = _skillreg()
    try:
        m = parse_manifest(text, fmt, source=source)
    except Exception as e:
        return json.dumps(_err(f"parse failed: {e}"), indent=2)
    res = reg.add(m)
    res["warnings"] = list(reg.warnings)
    return json.dumps(res, indent=2)


@mcp.tool()
def skill_verify(skill_id: str) -> str:
    """Report a registered skill's trust level: signed-trusted | signed-unknown |
    unsigned-builtin | unsigned-local | invalid. Keyring from env HYDRA_SKILL_KEYS.

    Args:
        skill_id: a registered skill id
    """
    reg = _skillreg()
    if not reg.get(skill_id):
        return json.dumps(_err(f"unknown skill '{skill_id}'"), indent=2)
    return json.dumps({"id": skill_id, "trust": reg.trust_of(skill_id)}, indent=2)


@mcp.tool()
def skill_resolve(skill_id: str) -> str:
    """Resolve a skill's SemVer dependency closure (deps first). Errors on a missing
    dependency, version mismatch, or a dependency cycle.

    Args:
        skill_id: a registered skill id
    """
    from hydra.skill_registry import DependencyError
    try:
        return json.dumps({"order": _skillreg().resolve(skill_id)}, indent=2)
    except DependencyError as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def skill_list() -> str:
    """List registered skills with their source + trust level."""
    reg = _skillreg()
    out = [{"id": sid, "source": reg.get(sid).source, "trust": reg.trust_of(sid)}
           for sid in reg.names()]
    return json.dumps({"skills": out, "warnings": list(reg.warnings)}, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  HITL RISK TIERS & PENTEST WORKFLOW ENGINE  (architecture spec Parts 8 & 9)
# ══════════════════════════════════════════════════════════════════════════════
# Risk classification + tiered approval policy (advisory; the real modal is the
# harness's), and the pentest lifecycle state machine (scope→…→reporting) with
# approval-gated transitions, checkpoints, and halt/resume recovery.

_WORKFLOW = None


def _workflow():
    global _WORKFLOW
    if _WORKFLOW is None:
        from hydra.workflow import PentestWorkflow
        _WORKFLOW = PentestWorkflow()
    return _WORKFLOW


@mcp.tool()
def hitl_classify(tool: str, command: str = "", operator_mode: bool = False) -> str:
    """Classify a tool call's HITL risk tier and the approval policy that applies:
    low (auto) | medium (allow-once/session/deny) | high (once/workflow/deny) |
    critical (once/deny/emergency-stop) | prohibited (HARD DENY). Operator mode
    auto-approves friction up to critical; prohibitions + scope gate stay hard.

    Args:
        tool: the tool name to classify
        command: the shell command (for shell_exec risk heuristics)
        operator_mode: simulate operator/YOLO friction-skip
    """
    from hydra.hitl import ApprovalPolicy
    args = {"command": command} if command else {}
    return json.dumps(ApprovalPolicy(operator_mode=operator_mode).evaluate(tool, args), indent=2)


@mcp.tool()
def workflow_pentest(action: str, run_id: str = "", engagement_id: str = "", target: str = "",
                     to_state: str = "", approve: bool = True, note: str = "",
                     checkpoint_json: str = "") -> str:
    """Drive the pentest lifecycle state machine (scope→recon→enumeration→validation
    →exploitation→evidence→coverage_review→reporting→done). Transitions into
    exploitation/evidence require approval; halt/resume recover from a checkpoint.

    Args:
        action: create | status | advance | checkpoint | halt | resume | list
        run_id: workflow run id (for all but create/list)
        engagement_id, target: for create
        to_state: target state (for advance)
        approve: approval decision for high-consequence transitions (advance)
        note: free-text note
        checkpoint_json: JSON snapshot (for checkpoint)
    """
    from hydra.workflow import WorkflowError
    w = _workflow()
    try:
        if action == "create":
            if not engagement_id or not target:
                return json.dumps(_err("create requires engagement_id and target"), indent=2)
            return json.dumps({"run_id": w.create(engagement_id, target), "state": "scope"}, indent=2)
        if action == "status":
            return json.dumps(w.get(run_id) or _err(f"unknown run {run_id}"), indent=2)
        if action == "list":
            return json.dumps({"runs": w.list_runs()}, indent=2)
        if action == "advance":
            return json.dumps(w.advance(run_id, to_state, approver=lambda _s: bool(approve),
                                        note=note), indent=2)
        if action == "checkpoint":
            data = json.loads(checkpoint_json) if checkpoint_json else {}
            return json.dumps(w.checkpoint(run_id, data), indent=2)
        if action == "halt":
            return json.dumps(w.halt(run_id, reason=note or "emergency-stop"), indent=2)
        if action == "resume":
            return json.dumps(w.resume(run_id), indent=2)
        return json.dumps(_err(f"unknown action '{action}'"), indent=2)
    except (WorkflowError, json.JSONDecodeError) as e:
        return json.dumps(_err(str(e)), indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  DYNAMIC MCP DISCOVERY  (architecture spec Part 10)
# ══════════════════════════════════════════════════════════════════════════════
# Operator-declared external MCP servers → discover/validate/namespace their tools
# with trust scoring + isolation. Unknown-server tools are gated (requires-permission
# + HIGH risk) and namespaced mcp:<server>:<tool> so they cannot shadow a core tool.

_MCP_REGISTRY = None


def _mcpreg():
    global _MCP_REGISTRY
    if _MCP_REGISTRY is None:
        from hydra.mcp_registry import MCPServerRegistry
        _MCP_REGISTRY = MCPServerRegistry()
    return _MCP_REGISTRY


@mcp.tool()
def mcp_declare(name: str, command: str, args: str = "", trust_class: str = "unknown",
                persist: bool = False) -> str:
    """Declare an external MCP server in the registry. trust_class drives how its
    tools are gated: trusted (not gated) | local (gated) | unknown (gated, HIGH risk).

    Args:
        name: server name
        command: launch command
        args: comma-separated args
        trust_class: trusted | local | unknown
        persist: write to data/mcp_servers.json
    """
    from hydra.mcp_registry import DiscoveryError
    arglist = [a.strip() for a in args.split(",") if a.strip()]
    try:
        return json.dumps(_mcpreg().declare(name, command, args=arglist,
                          trust_class=trust_class, persist=persist), indent=2)
    except DiscoveryError as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def mcp_servers() -> str:
    """List declared external MCP servers + their trust classes."""
    return json.dumps({"servers": _mcpreg().servers()}, indent=2)


@mcp.tool()
def mcp_discovered_tools() -> str:
    """List tools discovered from external MCP servers (namespaced) with trust +
    risk + whether they require permission."""
    return json.dumps({"tools": _mcpreg().tools()}, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTERPRISE: ENGAGEMENTS + RBAC + REPORT EXPORT  (architecture spec — enterprise)
# ══════════════════════════════════════════════════════════════════════════════
# Multi-client engagement objects (client/SoW/team/scope) with role-based access
# control (admin > lead > operator > viewer), and findings export to SARIF / Markdown
# / JSON for client deliverables + CI security ingestion.

_ENGAGEMENT_STORE = None


def _engagements():
    global _ENGAGEMENT_STORE
    if _ENGAGEMENT_STORE is None:
        from hydra.engagement import EngagementStore
        _ENGAGEMENT_STORE = EngagementStore()
    return _ENGAGEMENT_STORE


@mcp.tool()
def engagement(action: str, engagement_id: str = "", client: str = "", name: str = "",
               scope: str = "", sow_start: str = "", sow_end: str = "", owner: str = "",
               username: str = "", role: str = "") -> str:
    """Manage multi-client engagements + team membership.

    Args:
        action: create | get | list | add_member
        engagement_id: target engagement (get / add_member)
        client/name/scope/sow_start/sow_end/owner: for create (scope = comma-separated)
        username/role: for add_member (role: admin|lead|operator|viewer)
    """
    es = _engagements()
    try:
        if action == "create":
            if not client or not name:
                return json.dumps(_err("create requires client and name"), indent=2)
            scopes = [s.strip() for s in scope.split(",") if s.strip()]
            eid = es.create(client, name, scope=scopes, sow_start=sow_start,
                            sow_end=sow_end, owner=owner)
            return json.dumps({"engagement_id": eid}, indent=2)
        if action == "get":
            return json.dumps(es.get(engagement_id) or _err(f"unknown {engagement_id}"), indent=2)
        if action == "list":
            return json.dumps({"engagements": es.list()}, indent=2)
        if action == "add_member":
            return json.dumps(es.add_member(engagement_id, username, role), indent=2)
        return json.dumps(_err(f"unknown action '{action}'"), indent=2)
    except (ValueError, KeyError) as e:
        return json.dumps(_err(str(e)), indent=2)


@mcp.tool()
def rbac_check(engagement_id: str, username: str, rbac_action: str) -> str:
    """RBAC check: may `username` perform `rbac_action` on this engagement? Actions:
    read, run_recon/scan, create/validate/confirm/report_finding, run_exploit,
    record_coverage, export_report, manage_team/engagement/scope.

    Args:
        engagement_id: target engagement
        username: the user
        rbac_action: the action to authorize
    """
    return json.dumps(_engagements().authorize(engagement_id, username, rbac_action), indent=2)


@mcp.tool()
def report_export(engagement_id: str, fmt: str = "markdown") -> str:
    """Export an engagement's findings to a client/CI deliverable.

    Args:
        engagement_id: the engagement whose findings to export
        fmt: sarif | markdown | json
    """
    from hydra.reporting.export import to_json, to_markdown, to_sarif
    findings = _findings().list(engagement_id)
    eng = _engagements().get(engagement_id) or {"id": engagement_id}
    if fmt == "sarif":
        return to_sarif(findings)
    if fmt == "json":
        return to_json(findings, engagement=eng)
    if fmt in ("markdown", "md"):
        return to_markdown(findings, engagement=eng)
    return json.dumps(_err(f"unknown format '{fmt}' (sarif|markdown|json)"), indent=2)


@mcp.tool()
def generate_payloads(vuln_class: str, context: str = "any") -> str:
    """Context-aware PoC payload library (attack section): detection / proof-of-concept-grade payloads
    for a vuln class + injection context. Library lookup (no target named, not gated). Payloads are
    PoC-only (e.g. XSS pops alert(document.domain); SQLi proves via version()/time) — no exfiltration.

    Args:
        vuln_class: xss | sqli | ssti | ssrf | xxe | crlf | path_traversal | cmdi | open_redirect | lfi
        context: html_body | html_attr | js_string | url | sql | header | path | any
    """
    if vuln_class.lower() not in _VulnClass._value2member_map_:
        return json.dumps({"error": f"unknown vuln_class '{vuln_class}'",
                           "known": [v.value for v in _VulnClass]})
    try:
        ctx = _PayloadContext(context)
    except ValueError:
        ctx = _PayloadContext.ANY
    return json.dumps(_PayloadLibrary().report(_VulnClass(vuln_class.lower()), ctx), indent=2)


@mcp.tool()
def oob_payload(vuln_class: str, finding_id: str = "poc", callback_domain: str = "") -> str:
    """Out-of-band / blind detection payloads (attack section): mints a deterministic correlation
    token + callback under YOUR configured OOB domain (e.g. your interactsh/Collaborator) and emits
    blind payloads embedding it (blind SSRF/XXE/XSS/SQLi/cmdi). No live server is created here.

    Args:
        vuln_class: ssrf | xxe | xss | sqli | cmdi
        finding_id: stable id to correlate callbacks to (default "poc")
        callback_domain: your own OOB endpoint domain (e.g. "xxxx.oast.live"); omit for a placeholder
    """
    oc = _OOBCorrelator(_ListenerConfig(oob_domain=callback_domain or "oob.invalid"))
    token = oc.mint(finding_id, vuln_class.lower())
    return json.dumps({"token": token.to_dict(),
                       "payloads": oc.payloads(vuln_class.lower(), token.callback_url),
                       "listener_configured": oc.listener.configured,
                       "note": "point callback_domain at YOUR authorized OOB server to receive hits",
                       "advisory": True}, indent=2)


@mcp.tool()
def attack_queue(target: str, findings: str = "") -> str:
    """Intelligence-driven attack prioritization (attack section): rank candidate attacks for a target
    by severity + chain potential + capability backing. Authorization-gated (deny-by-default).

    Args:
        target: target url/host (must be bug-bounty in-scope)
        findings: JSON array of findings, e.g. '[{"id":"f1","vuln_class":"ssrf","severity":"low"}]'
    """
    decision = _AuthGate().authorize(target, "vulnerability_scan")
    if not decision.authorized:
        return json.dumps({"authorized": False, "reason": decision.reason, "queue": []}, indent=2)
    try:
        rows = json.loads(findings) if findings else []
        if not isinstance(rows, list):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "findings must be a JSON array of objects"})
    out = _AttackQueue().prioritize(target, rows)
    out["authorized"] = True
    return json.dumps(out, indent=2)


@mcp.tool()
def load_bounty_scope(url: str = "", platform: str = "", program_id: str = "",
                      raw_scope: str = "") -> str:
    """Load a bug bounty program's published scope and register it with the authorization gate —
    this is what AUTHORIZES its in-scope assets for active testing. Source it live from the program
    URL (HackerOne/Bugcrowd/...) or pass a raw scope dict.

    Args:
        url: program URL to fetch live (e.g. "https://hackerone.com/acme")
        platform: platform when using raw_scope (hackerone|bugcrowd|intigriti|yeswehack|custom)
        program_id: program handle when using raw_scope
        raw_scope: JSON object with at least an "in_scope" list (offline alternative to url)
    """
    loader = _ScopeLoader()
    try:
        if url:
            out = loader.load_url(url)
        elif raw_scope:
            out = loader.load_raw(platform or "custom", program_id or "program",
                                  json.loads(raw_scope))
        else:
            return json.dumps({"success": False, "error": "provide 'url' or 'raw_scope'"})
    except Exception as e:
        return json.dumps({"success": False, "error": f"scope load failed: {e}"})
    return json.dumps({"success": True, **out}, indent=2)


@mcp.tool()
def attack_execute(target: str, vuln_class: str, context: str = "any",
                   param: str = "q", rate_per_sec: float = 1.0) -> str:
    """Authorization-gated LIVE PoC execution (attack section): sends ONE PoC payload to an in-scope
    target via the gated, rate-limited HttpExecutor and returns reproducible evidence
    (request/response, curl, confirmed/suspected). DENY-BY-DEFAULT — a target not in a registered bug
    bounty scope returns `authorized: false` and sends NOTHING. PoC-only; never destructive/exfil/DoS.

    Args:
        target: in-scope target url/host
        vuln_class: xss | sqli | ssti | ssrf | xxe | crlf | path_traversal | cmdi | open_redirect | lfi
        context: injection context (html_body|html_attr|js_string|url|sql|header|path|any)
        param: query parameter to inject the payload into (default "q")
        rate_per_sec: max requests/sec (clamped to 0.1–5.0)
    """
    gate = _AuthGate()
    executor = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    res = _AttackWorkflow(gate=gate, executor=executor).run(
        target, vuln_class, context, execute=True, param=param)
    return json.dumps(res.to_dict(), indent=2)


@mcp.tool()
def attack_scan(target: str, vuln_class: str, context: str = "any",
                max_payloads: int = 6, max_points: int = 8, rate_per_sec: float = 1.0,
                confirm_dom: bool = False, headless: bool = True,
                baseline_samples: int = 1, fingerprint: str = "", extra_headers: str = "") -> str:
    """Authorization-gated DIFFERENTIAL scan (attack section): sends a benign baseline then iterates
    PoC payloads across discovered injection points (query/body/json/header/cookie/path), confirms via
    differential analysis (two-signal — incl. boolean-blind for SQLi), guards against trap/honeypot
    endpoints, adapts to WAF blocks, early-exits a point on first confirmation. Returns
    confirmed/suspected findings + reproducible evidence. Deny-by-default; PoC-only; rate-limited.

    Args:
        target: in-scope target url
        vuln_class: xss|sqli|ssti|ssrf|xxe|crlf|path_traversal|cmdi|open_redirect|lfi|nosqli|ldapi|prototype_pollution
        context: injection context (html_body|html_attr|js_string|url|sql|header|path|any)
        max_payloads: payloads per injection point (clamped 1–8)
        max_points: injection points to test (clamped 1–12)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
        confirm_dom: confirm reflective XSS via a REAL headless browser (needs Playwright; the strong
                     second signal). Falls back to the differential verdict if unavailable.
        headless: run the confirmation browser headless (default True)
        baseline_samples: sample the baseline N times for stability (clamped 1–3; cuts dynamic-page FPs)
        fingerprint: stack techs (e.g. "wordpress php mysql") → float stack-relevant payloads first
        extra_headers: JSON object of headers added to EVERY request (e.g. program attribution
                       '{"X_Bug_Bounty":"your_username"}'); applied via a header-only session
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    bc = None
    if confirm_dom:
        _browser = _BrowserConfirmer(headless=headless)
        bc = lambda url: _browser.confirm_xss(url)            # noqa: E731 (adapt to (url)->{confirmed})
    sess = None
    if extra_headers:
        try:
            sess = _SessionContext(name="hdr", headers=json.loads(extra_headers))
        except (ValueError, json.JSONDecodeError):
            return json.dumps({"error": "extra_headers must be a JSON object"})
    res = _AttackWorkflow(gate=gate, executor=ex, browser_confirmer=bc).scan(
        target, vuln_class, context, session=sess, max_payloads=max(1, min(max_payloads, 8)),
        max_points=max(1, min(max_points, 12)), record=True, confirm_dom=confirm_dom,
        baseline_samples=max(1, min(baseline_samples, 3)), fingerprint=fingerprint)
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_access_control(target: str, session_a: str, session_b: str,
                          owner_markers: str = "") -> str:
    """Authorization-gated IDOR / broken-access-control test (attack section): fetches the SAME
    resource as two identities and diffs the responses. Deny-by-default; PoC-only.

    Args:
        target: in-scope resource url
        session_a: JSON identity A, e.g. '{"name":"alice","bearer":"...","cookies":{"sid":"a"}}'
        session_b: JSON identity B (a different user/role)
        owner_markers: comma-separated strings unique to A's private data (strongest signal)
    """
    gate = _AuthGate()
    try:
        a, b = json.loads(session_a), json.loads(session_b)
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "session_a/session_b must be JSON objects"})
    sa = _SessionContext(name=a.get("name", "A"), bearer=a.get("bearer", ""),
                         cookies=a.get("cookies", {}) or {}, headers=a.get("headers", {}) or {})
    sb = _SessionContext(name=b.get("name", "B"), bearer=b.get("bearer", ""),
                         cookies=b.get("cookies", {}) or {}, headers=b.get("headers", {}) or {})
    markers = [m.strip() for m in owner_markers.split(",") if m.strip()]
    ex = _HttpExecutor(gate=gate, rate_per_sec=2.0)
    res = _AttackWorkflow(gate=gate, executor=ex).access_control_test(target, sa, sb, markers)
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_chain_execute(target: str, chain_id: str, rate_per_sec: float = 1.0) -> str:
    """Authorization-gated CHAIN execution (attack section): validates a chain template's testable
    stages in order against the target, recording demonstrable depth + realized severity. Each stage
    is gated; evidence is REDACTED (credentials/secrets masked); no auto-pivot. PoC-only.

    Args:
        target: in-scope target url
        chain_id: a chain template id (e.g. "ssrf_imds_takeover", "idor_ato", "xxe_ssrf_metadata")
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    wf = _AttackWorkflow(gate=gate, executor=ex)
    return json.dumps(_ChainExecutor(wf).execute(target, chain_id), indent=2)


@mcp.tool()
def attack_report(target: str, findings: str, chains: str = "", template: str = "") -> str:
    """Build a submission-ready report (attack section) from scan findings: executive summary,
    confirmed-vs-suspected split (deduped), per-finding PoC + remediation + CVSS 3.1, severity
    calibration (chaining elevates). Pure formatting (no target contact).

    Args:
        target: the assessed target
        findings: JSON array of findings (from attack_scan's confirmed_findings/suspected)
        chains: optional JSON array of executed-chain results (for severity elevation)
        template: "" for JSON, or "hackerone" / "bugcrowd" for a Markdown submission
    """
    try:
        f = json.loads(findings) if findings else []
        c = json.loads(chains) if chains else []
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "findings/chains must be JSON arrays"})
    reporter = _AttackReporter()
    report = reporter.build(target, f, c)
    if template in ("hackerone", "bugcrowd"):
        return json.dumps({"target": target, "template": template,
                           "markdown": reporter.to_markdown(report, template)}, indent=2)
    return json.dumps(report, indent=2)


@mcp.tool()
def attack_scan_crawled(urls: str, vuln_class: str, context: str = "any",
                        max_seeds: int = 12, rate_per_sec: float = 1.0,
                        concurrency: int = 1, resume: bool = False,
                        confirm_dom: bool = False, headless: bool = True,
                        extra_headers: str = "") -> str:
    """Authorization-gated scan over a CRAWL's URLs (attack section): de-dupes a list (e.g. from
    `katana_crawl` / `gau_urls`) to distinct injectable endpoints, then differential-scans each. Every
    target is independently gated (deny-by-default); PoC-only; rate-limited.

    Args:
        urls: whitespace/comma-separated URL list (pipe katana/gau output here)
        vuln_class: xss|sqli|ssti|ssrf|xxe|crlf|path_traversal|cmdi|open_redirect|lfi|nosqli|ldapi|prototype_pollution
        context: injection context (default any)
        max_seeds: max distinct endpoints to scan (clamped 1–25)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
        concurrency: parallel endpoints (clamped 1–8; the executor is the rate-limited boundary)
        resume: skip endpoints already scanned in a prior run (cross-run dedup via ScanState)
        confirm_dom: confirm reflective XSS via a REAL headless browser (needs Playwright)
        headless: run the confirmation browser headless (default True)
        extra_headers: JSON object of headers added to EVERY request (e.g. '{"X_Bug_Bounty":"user"}')
    """
    url_list = [u.strip() for u in urls.replace(",", " ").split() if u.strip()]
    if not url_list:
        return json.dumps({"error": "provide one or more URLs"})
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    bc = None
    if confirm_dom:
        _browser = _BrowserConfirmer(headless=headless)
        bc = lambda url: _browser.confirm_xss(url)            # noqa: E731
    sess = None
    if extra_headers:
        try:
            sess = _SessionContext(name="hdr", headers=json.loads(extra_headers))
        except (ValueError, json.JSONDecodeError):
            return json.dumps({"error": "extra_headers must be a JSON object"})
    res = _AttackWorkflow(gate=gate, executor=ex, browser_confirmer=bc).scan_many(
        url_list, vuln_class, context, session=sess, max_seeds=max(1, min(max_seeds, 25)),
        record=True, concurrency=max(1, min(concurrency, 8)), resume=resume, confirm_dom=confirm_dom)
    return json.dumps(res, indent=2)


def _interactsh_session_path():
    import pathlib
    return pathlib.Path(os.environ.get("HYDRA_INTERACTSH_SESSION")
                        or (pathlib.Path(__file__).resolve().parent / "data" / "interactsh_session.json"))


def _load_interactsh_client():
    """Load the persisted interactsh session (keypair etc.), or None."""
    try:
        p = _interactsh_session_path()
        if p.exists():
            return _InteractshClient.from_dict(json.loads(p.read_text(encoding="utf-8")),
                                               verify_tls=False)
    except Exception:
        pass
    return None


@mcp.tool()
def interactsh_register(server: str = "oast.fun") -> str:
    """Register an interactsh OOB session (attack section): generates a keypair, registers with the
    interactsh server, persists the session locally, and returns the OOB domain to embed in payloads.
    `oob_confirm` then polls + decrypts this session automatically. Talks only to the OOB server.

    Args:
        server: interactsh server host (default oast.fun; use your own self-hosted instance if you have one)
    """
    try:
        client = _InteractshClient(server=server, verify_tls=False)
        ok = client.register()
        p = _interactsh_session_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(client.to_dict(), indent=2), encoding="utf-8")
    except Exception as e:
        return json.dumps({"success": False, "error": f"interactsh register failed: {e}"})
    return json.dumps({"success": True, "registered": ok, "oob_domain": client.domain,
                       "note": "embed <token>.<oob_domain> in OOB payloads; then call oob_confirm"},
                      indent=2)


@mcp.tool()
def oob_confirm(finding_id: str, vuln_class: str, poll_url: str = "", oob_domain: str = "") -> str:
    """Confirm a blind/OOB finding (attack section): re-mints the deterministic OOB token for this
    finding, polls YOUR collaborator, and correlates received interactions back to the token →
    confirmed blind SSRF/XXE/RCE. With no `poll_url`, uses the persisted interactsh session
    (`interactsh_register`). Talks only to the OOB endpoint, never the target.

    Args:
        finding_id: the id used when the OOB payload was issued (see `oob_payload`)
        vuln_class: ssrf | xxe | xss | sqli | cmdi
        poll_url: a generic collaborator poll endpoint (JSON interactions); omit to use interactsh
        oob_domain: your OOB domain (for token host reconstruction; optional)
    """
    poller, domain = None, oob_domain
    if poll_url:
        poller = _OOBPoller(poll_url, verify_tls=False).poll
    else:
        client = _load_interactsh_client()
        if client is not None:
            poller = client.poll
            domain = domain or client.domain
    oc = _OOBCorrelator(_ListenerConfig(oob_domain=domain or "oob.invalid"))
    oc.mint(finding_id, vuln_class.lower())
    return json.dumps(_OOBConfirmer(oc, poller).confirm(), indent=2)


@mcp.tool()
def attack_recon_scan(target: str, vuln_class: str, context: str = "any", depth: int = 2,
                      use_gau: bool = False, max_seeds: int = 12, rate_per_sec: float = 1.0,
                      concurrency: int = 1, resume: bool = False) -> str:
    """One-step recon→scan (attack section): crawls an in-scope target (katana, optionally gau),
    de-dupes the discovered URLs to distinct injectable endpoints, and differential-scans each. Every
    target is independently authorization-gated; PoC-only; rate-limited. Falls back to the target URL
    if the crawlers find nothing / aren't installed.

    Args:
        target: in-scope target url
        vuln_class: xss | sqli | ssti | ssrf | xxe | crlf | path_traversal | cmdi | open_redirect | lfi
        context: injection context (default any)
        depth: katana crawl depth (1–5)
        use_gau: also pull historical URLs via gau
        max_seeds: max distinct endpoints to scan (clamped 1–25)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    urls = [target]
    try:
        kr = json.loads(katana_crawl(target, depth=max(1, min(depth, 5))))
        urls += kr.get("endpoints", [])
    except Exception:
        pass
    if use_gau:
        try:
            from urllib.parse import urlparse as _up
            gr = json.loads(gau_urls(_up(target).hostname or target))
            urls += gr.get("urls", [])
        except Exception:
            pass
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    res = _AttackWorkflow(gate=gate, executor=ex).scan_many(
        urls, vuln_class, context, max_seeds=max(1, min(max_seeds, 25)), record=True,
        concurrency=max(1, min(concurrency, 8)), resume=resume)
    res["crawled_urls"] = len(urls)
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_login(login_url: str, fields: str, json_body: bool = False, name: str = "auth",
                 csrf_field: str = "", csrf_url: str = "") -> str:
    """Authorization-gated login automation (attack section): POSTs YOUR test credentials to an
    in-scope login endpoint and returns the captured session (cookies + bearer) for use with
    `attack_access_control` / authenticated scans. CSRF/multi-step aware. Deny-by-default; the
    operator's own accounts only.

    Args:
        login_url: in-scope login endpoint
        fields: JSON object of form/JSON fields (e.g. '{"username":"u","password":"p"}')
        json_body: send the body as JSON instead of form-encoded
        name: identity name for the returned session
        csrf_field: anti-CSRF field name to pre-fetch (e.g. "csrf_token"); omit if none
        csrf_url: page to GET for the CSRF token (default: the login URL)
    """
    gate = _AuthGate()
    try:
        f = json.loads(fields)
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "fields must be a JSON object"})
    try:
        s = _LoginFlow(gate=gate).login(login_url, f, json_body=json_body, name=name,
                                        csrf_field=csrf_field, csrf_url=csrf_url)
    except Exception as e:
        return json.dumps({"success": False, "error": f"login failed: {e}"})
    if s is None:
        return json.dumps({"success": False, "authorized": False,
                           "error": "login endpoint not in a registered bug bounty scope"})
    return json.dumps({"success": True, "authorized": True,
                       "session": {"name": s.name, "bearer": s.bearer, "cookies": s.cookies},
                       "note": "pass this session JSON to attack_access_control / authenticated scans"},
                      indent=2)


@mcp.tool()
def attack_save_findings(target: str, findings: str) -> str:
    """Close the loop (attack section): write TWO-SIGNAL-CONFIRMED findings to the findings store
    (`save_finding`) + attack memory, AND record each as a verification SUCCESS for its vuln-class so
    it actually feeds Phase-F → Phase-P effectiveness → Phase-S/T/U re-ranking (idempotent per
    target/class/point). Only `confirmed` findings are recorded (suspected/single-signal skipped).

    Args:
        target: the assessed target
        findings: JSON array of findings (from attack_scan's confirmed_findings)
    """
    try:
        f = json.loads(findings) if findings else []
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "findings must be a JSON array"})

    def _save(title, severity, tgt, description, vuln_class):
        return save_finding(title, severity, tgt, description, finding_type=vuln_class)
    return json.dumps(_FindingPublisher(save_fn=_save).publish(target, f), indent=2)


@mcp.tool()
def attack_graphql(url: str, rate_per_sec: float = 1.0) -> str:
    """Authorization-gated GraphQL testing (attack section): introspection, field-suggestion leakage,
    GET-introspection, batching. Detection/PoC only (reads schema/errors, mutates nothing).
    Deny-by-default.

    Args:
        url: in-scope GraphQL endpoint
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    d = gate.authorize(url, "vulnerability_scan")
    if not d.authorized:
        return json.dumps({"authorized": False, "reason": d.reason, "checks": []})
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    t = _GraphQLTester()
    rows = []
    for chk in t.requests(url):
        resp = ex(chk["request"])
        verdict, reason = t.analyze(chk["name"], resp)
        rows.append({"check": chk["name"], "verdict": verdict, "reason": reason,
                     "status": resp.get("status")})
    return json.dumps({"url": url, "authorized": True, "checks": rows,
                       "confirmed": any(r["verdict"] == "confirmed" for r in rows),
                       "advisory": True}, indent=2)


@mcp.tool()
def attack_jwt(token: str, public_key: str = "") -> str:
    """JWT analysis + test-token forging (attack section): decodes claims, recovers a weak HMAC secret
    (small common list), and forges alg=none / HS-RS-confusion / kid-injection test tokens to REPLAY
    against an authorized target (PoC). Local crypto only — no target contact, not gated.

    Args:
        token: the JWT to analyze
        public_key: server RSA public key PEM (enables HS/RS algorithm-confusion forging)
    """
    ja = _JWTAnalyzer()
    out = ja.analyze(token)
    if "error" not in out:
        try:
            out["forged"] = {"alg_none": ja.forge_none(token),
                             "kid_injection": ja.inject_kid(token)}
            if public_key:
                out["forged"]["alg_confusion_hs256"] = ja.forge_alg_confusion(token, public_key)
        except Exception:
            pass
    return json.dumps(out, indent=2)


@mcp.tool()
def attack_web_probe(url: str, probe: str = "cors", rate_per_sec: float = 1.0) -> str:
    """Authorization-gated web-class probe (attack section): cors | cache_poison | host_header |
    smuggle. cache_poison/host use BENIGN markers (detection only — never stores attacker content).
    `smuggle` is ADVISORY/PLAN ONLY (never auto-sent — desync can affect co-tenants). Deny-by-default.

    Args:
        url: in-scope target url
        probe: cors | cache_poison | host_header | smuggle
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    if probe == "smuggle":
        return json.dumps(_SmugglingPlan().plan(url), indent=2)     # plan only; nothing sent
    gate = _AuthGate()
    d = gate.authorize(url, "vulnerability_scan")
    if not d.authorized:
        return json.dumps({"authorized": False, "reason": d.reason})
    probes = {"cors": _CORSProbe(), "cache_poison": _CachePoison(), "host_header": _HostHeader()}
    p = probes.get(probe)
    if p is None:
        return json.dumps({"error": f"unknown probe '{probe}'",
                           "known": ["cors", "cache_poison", "host_header", "smuggle"]})
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    resp = ex(p.request(url))
    verdict, reason = p.analyze(resp)
    return json.dumps({"url": url, "probe": probe, "authorized": True, "verdict": verdict,
                       "reason": reason, "status": resp.get("status"), "advisory": True}, indent=2)


@mcp.tool()
def attack_race(url: str, n: int = 10) -> str:
    """Authorization-gated race-condition test (attack section): fires a BOUNDED number of concurrent
    identical requests and reports the outcome distribution (limit-overrun / TOCTOU candidate).
    Deny-by-default; bounded (≤30); PoC-only — never amplifies the action.

    Args:
        url: in-scope target url (a state-changing endpoint is most meaningful)
        n: concurrent requests (clamped 2–30)
    """
    return json.dumps(_RaceTester(gate=_AuthGate()).test({"method": "GET", "url": url}, n=n), indent=2)


@mcp.tool()
def attack_privesc(base_url: str, session: str, paths: str = "", admin_session: str = "") -> str:
    """Authorization-gated privilege-escalation / RBAC test (attack section): requests privileged
    endpoints as a LOW-privilege identity (optionally diffed against admin) and flags any reachable as
    a broken-access candidate. Deny-by-default; PoC-only.

    Args:
        base_url: in-scope base url
        session: JSON low-priv identity (e.g. '{"name":"user","cookies":{"sid":"u"}}')
        paths: comma-separated privileged paths (default: a built-in list)
        admin_session: optional JSON admin identity (sharpens the diff)
    """
    gate = _AuthGate()
    d = gate.authorize(base_url, "active_recon")
    if not d.authorized:
        return json.dumps({"authorized": False, "reason": d.reason})
    try:
        low = json.loads(session)
        adm = json.loads(admin_session) if admin_session else None
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "session/admin_session must be JSON objects"})
    low_s = _SessionContext(name=low.get("name", "low"), bearer=low.get("bearer", ""),
                            cookies=low.get("cookies", {}) or {}, headers=low.get("headers", {}) or {})
    adm_s = (_SessionContext(name="admin", bearer=adm.get("bearer", ""),
                             cookies=adm.get("cookies", {}) or {}, headers=adm.get("headers", {}) or {})
             if adm else None)
    plist = [p.strip() for p in paths.split(",") if p.strip()] or None
    ex = _HttpExecutor(gate=gate, rate_per_sec=2.0)
    return json.dumps(_PrivEsc(ex).test(base_url, low_s, plist, adm_s), indent=2)


@mcp.tool()
def attack_oob_test(target: str, vuln_class: str = "ssrf", finding_id: str = "poc",
                    poll_wait: float = 0.0) -> str:
    """Authorization-gated ACTIVE blind-vuln test (attack section): injects OOB payloads (SSRF/cmdi
    into injection points, XXE as an XML body) that embed a per-finding callback under your registered
    interactsh session, then polls + correlates → confirmed blind SSRF/XXE/cmdi. Requires
    `interactsh_register` first. Deny-by-default; PoC-only (benign callback, no exfiltration).

    Args:
        target: in-scope target url
        vuln_class: ssrf | xxe | cmdi (blind/OOB classes)
        finding_id: stable id to correlate the callback (default "poc")
        poll_wait: seconds to wait for async callbacks before polling (bounded ≤30)
    """
    client = _load_interactsh_client()
    if client is None:
        return json.dumps({"error": "no interactsh session — call interactsh_register first"})
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=1.0)
    tester = _OOBAttackTester(gate=gate, executor=ex,
                              correlator=_OOBCorrelator(_ListenerConfig(oob_domain=client.domain)),
                              poller=client.poll, oob_domain=client.domain)
    return json.dumps(tester.test(target, vuln_class, finding_id, poll_wait=poll_wait), indent=2)


@mcp.tool()
def attack_campaign(target: str, crawl: bool = False, classes: str = "", max_seeds: int = 8,
                    publish: bool = True, rate_per_sec: float = 1.0) -> str:
    """Authorization-gated end-to-end CAMPAIGN (attack section — the capstone): one call runs
    seeds → differential multi-class scan (two-signal) → confirmed findings → exploit-chain matching →
    (loop-back) publish confirmed findings to the knowledge graph + verification learning → submission
    report. Deny-by-default; PoC-only; rate-limited; bounded.

    Args:
        target: in-scope target url
        crawl: also crawl the target (katana) to seed distinct endpoints
        classes: comma-separated vuln classes (default: xss,sqli,open_redirect,lfi,ssti)
        max_seeds: max distinct endpoints to scan (clamped 1–20)
        publish: feed confirmed findings back into the intelligence (default True)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    seeds = [target]
    if crawl:
        try:
            seeds += json.loads(katana_crawl(target, depth=2)).get("endpoints", [])
        except Exception:
            pass
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    wf = _AttackWorkflow(gate=gate, executor=ex)

    def _save(title, severity, tgt, description, vuln_class):
        return save_finding(title, severity, tgt, description, finding_type=vuln_class)
    publisher = _FindingPublisher(save_fn=_save)
    cls = [c.strip() for c in classes.split(",") if c.strip()] or None
    campaign = _AttackCampaign(wf, publisher=publisher, classes=cls)
    res = campaign.run(target, urls=seeds, max_seeds=max(1, min(max_seeds, 20)), publish=publish)
    return json.dumps(res, indent=2)


def _parse_session(blob: str, default_name: str):
    """Parse a JSON identity blob into a SessionContext (empty → anonymous)."""
    if not blob:
        return _SessionContext(name=default_name)
    s = json.loads(blob)
    return _SessionContext(name=s.get("name", default_name), bearer=s.get("bearer", ""),
                           cookies=s.get("cookies", {}) or {}, headers=s.get("headers", {}) or {})


@mcp.tool()
def attack_api(target: str, check: str, session: str = "", session_b: str = "",
               owner_markers: str = "", id_param: str = "", ids: str = "",
               functions: str = "", base_body: str = "", method: str = "PATCH",
               rate_per_sec: float = 1.0) -> str:
    """Authorization-gated OWASP API Top 10 test (attack section): bola | bfla | mass_assignment |
    excessive_data_exposure. Reuses the dual-identity model + gated executor. Deny-by-default; PoC-only
    (mass-assignment uses benign flag values; data-exposure only LABELS leaked keys, never stores them).

    Args:
        target: in-scope API resource/base url
        check: bola | bfla | mass_assignment | excessive_data_exposure
        session: JSON identity (owner/low-priv/caller) e.g. '{"name":"a","bearer":"...","cookies":{}}'
        session_b: JSON second identity (BOLA: the other user; BFLA: optional admin)
        owner_markers: BOLA — comma-separated strings unique to A's private data
        id_param: BOLA — query param holding the object id (enables foreign-id enumeration)
        ids: BOLA — comma-separated object ids to enumerate as identity B
        functions: BFLA — comma-separated "METHOD /path" pairs (default: a built-in list)
        base_body: mass_assignment — JSON base object to which privileged fields are added
        method: mass_assignment — write method (PATCH/PUT/POST)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    try:
        tester = _APIAttackTester(ex, gate=gate)
        sess = _parse_session(session, "caller")
        if check == "bola":
            sb = _parse_session(session_b, "B")
            markers = [m.strip() for m in owner_markers.split(",") if m.strip()] or None
            id_list = [i.strip() for i in ids.replace(",", " ").split() if i.strip()] or None
            res = tester.bola(target, sess, sb, owner_markers=markers, id_param=id_param,
                              ids=id_list)
        elif check == "bfla":
            adm = _parse_session(session_b, "admin") if session_b else None
            funcs = None
            if functions:
                funcs = []
                for item in functions.split(","):
                    parts = item.strip().split(None, 1)
                    funcs.append((parts[0].upper(), parts[1]) if len(parts) == 2
                                 else ("GET", parts[0]))
            res = tester.bfla(target, sess, functions=funcs, admin_session=adm)
        elif check == "mass_assignment":
            bb = json.loads(base_body) if base_body else None
            res = tester.mass_assignment(target, sess, base_body=bb, method=method)
        elif check == "excessive_data_exposure":
            res = tester.excessive_data_exposure(target, sess)
        else:
            return json.dumps({"error": f"unknown check '{check}'",
                               "known": ["bola", "bfla", "mass_assignment",
                                         "excessive_data_exposure"]})
    except (ValueError, json.JSONDecodeError) as e:
        return json.dumps({"error": f"invalid JSON argument: {e}"})
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_oauth(authorize_url: str, evil: str = "https://evil.example.com",
                 rate_per_sec: float = 1.0) -> str:
    """Authorization-gated OAuth/OIDC test (attack section): statically flags missing state / missing
    PKCE / implicit-flow token leakage / broad scope, AND actively tests redirect_uri validation by
    sending tampered variants — confirmed when the server honours an attacker-controlled destination.
    Deny-by-default; PoC-only (never completes a token exchange).

    Args:
        authorize_url: in-scope OAuth/OIDC authorize endpoint URL (with its query params)
        evil: attacker placeholder destination to test redirect_uri against
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    tester = _OAuthTester(executor=ex, gate=gate)
    out = {"static_analysis": tester.analyze(authorize_url),
           "redirect_uri_test": tester.test_redirect_uri(authorize_url, evil)}
    return json.dumps(out, indent=2)


@mcp.tool()
def attack_saml(saml_response: str) -> str:
    """SAML Response analysis (attack section): decodes a SAML Response and flags unsigned /
    multi-assertion / comment-injection conditions, and emits XSW (signature-wrapping) test vectors as
    advisory PoC artifacts. Local crypto only — no target contact, not gated, never replayed.

    Args:
        saml_response: base64 (or raw XML) SAML Response
    """
    return json.dumps(_SAMLAnalyzer().analyze(saml_response), indent=2)


@mcp.tool()
def attack_stored(submit_url: str, observe_urls: str, vuln_class: str = "xss",
                  field: str = "", method: str = "POST", body: str = "", json_body: bool = False,
                  session: str = "", oob: bool = False, finding_id: str = "stored-poc",
                  poll_wait: float = 0.0, rate_per_sec: float = 1.0) -> str:
    """Authorization-gated STORED / second-order test (attack section): submits a uniquely-tagged
    payload at one endpoint, then OBSERVES other endpoints for the tag — catching stored XSS / stored
    SSRF / second-order injection that single-request scans miss. In-band canary correlation (+ real
    DOM execution for stored XSS = two-signal) or OOB mode for blind/second-order. Every URL is
    independently gated (deny-by-default); PoC-only.

    Args:
        submit_url: in-scope endpoint that PERSISTS input (e.g. a profile/comment write)
        observe_urls: whitespace/comma-separated endpoints where the stored value may surface
        vuln_class: xss | ssti | html_injection | ssrf | xxe | cmdi (last three imply oob=True)
        field: the field to inject (default: first injectable point of the submit request)
        method: submit HTTP method (default POST)
        body: submit body to seed (form or JSON object); the field is injected into it
        json_body: treat `body` as JSON
        session: JSON identity to authenticate both submit and observe
        oob: blind/second-order via your interactsh callback (requires interactsh_register)
        finding_id: stable id for OOB correlation
        poll_wait: seconds to wait for a (possibly delayed) OOB callback (bounded ≤30)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    observe = [u.strip() for u in observe_urls.replace(",", " ").split() if u.strip()]
    submit_req = {"method": method.upper(), "url": submit_url, "headers": {}}
    if body:
        submit_req["body"] = body
        if json_body:
            submit_req["headers"]["Content-Type"] = "application/json"
    try:
        sess = _parse_session(session, "auth") if session else None
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "session must be a JSON object"})
    correlator = None
    poller = None
    if oob:
        client = _load_interactsh_client()
        if client is None:
            return json.dumps({"error": "OOB mode needs an interactsh session — call interactsh_register first"})
        correlator = _OOBCorrelator(_ListenerConfig(oob_domain=client.domain))
        poller = client.poll
    tester = _StoredVulnTester(gate=gate, executor=ex, correlator=correlator)
    res = tester.test(submit_req, observe, vuln_class=vuln_class, field=field, session=sess,
                      oob=oob, finding_id=finding_id, poll_wait=poll_wait, poller=poller)
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_param_mine(url: str, session: str = "", wordlist: str = "", batch: int = 20,
                      max_requests: int = 80, rate_per_sec: float = 2.0) -> str:
    """Authorization-gated PARAMETER mining (attack section): Arjun-style reflection-based discovery of
    hidden/undocumented query parameters — sends batched candidate names with a canary, then isolates
    the responsible parameter. Returns injectable endpoints to feed `attack_scan_crawled`. Deny-by-
    default; PoC-only; bounded request budget.

    Args:
        url: in-scope endpoint to mine
        session: optional JSON identity to authenticate
        wordlist: optional comma/space-separated parameter names (default: a built-in high-signal list)
        batch: parameters per batched probe (clamped 5–50)
        max_requests: hard request budget (clamped 5–300)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    try:
        sess = _parse_session(session, "auth") if session else None
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "session must be a JSON object"})
    words = [w.strip() for w in wordlist.replace(",", " ").split() if w.strip()] or None
    res = _ParameterMiner(gate=gate, executor=ex).mine(
        url, session=sess, wordlist=words, batch=max(5, min(batch, 50)),
        max_requests=max(5, min(max_requests, 300)))
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_js_extract(js: str = "", url: str = "") -> str:
    """Extract endpoints / parameter names / high-signal secrets from JavaScript (attack section).
    Pure analysis — provide JS text directly, or a URL to fetch (gated). Secrets are previews only
    (values redacted). Not a scanner; feed discovered endpoints/params to the injection scanners.

    Args:
        js: raw JavaScript source to analyze
        url: alternatively, an in-scope .js URL to fetch and analyze (gated)
    """
    text = js
    if not text and url:
        gate = _AuthGate()
        d = gate.authorize(url, "active_recon")
        if not d.authorized:
            return json.dumps({"authorized": False, "reason": d.reason})
        resp = _HttpExecutor(gate=gate, rate_per_sec=2.0)({"method": "GET", "url": url, "headers": {}})
        text = resp.get("body_snippet") or ""
    if not text:
        return json.dumps({"error": "provide js text or an in-scope url"})
    return json.dumps(_JSEndpointExtractor().extract(text), indent=2)


@mcp.tool()
def attack_reverify(finding: str, bundle: bool = True, rate_per_sec: float = 1.0) -> str:
    """Re-verify a stored finding (attack section): replays the finding's saved request against a fresh
    baseline and re-runs the differential + two-signal logic → reproduces true/false with fresh
    evidence; optionally emits a self-contained, replayable PoC bundle. Deny-by-default; PoC-only.

    Args:
        finding: a confirmed finding JSON (with its `evidence.request`), e.g. an item from
                 attack_scan's confirmed_findings
        bundle: also build a replayable PoC bundle (curl + request/response + indicators)
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    try:
        f = json.loads(finding)
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "finding must be a JSON object"})
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    out = _FindingReverifier(gate=gate, executor=ex).reverify(f)
    if bundle:
        out["poc_bundle"] = _build_bundle(f)
    return json.dumps(out, indent=2)


@mcp.tool()
def attack_triage(findings: str, target: str = "", platform: str = "hackerone",
                  known_signatures: str = "") -> str:
    """Program-aware triage + submission-readiness (attack section): maps each finding's CVSS to the
    platform severity (HackerOne/Bugcrowd P-scale) + advisory bounty band, and runs the
    submission-readiness gate (confirmed? two signals? proof attached? in-scope? not duplicate?).
    Pure/advisory (the in-scope check uses the gate; sends nothing).

    Args:
        findings: JSON array of findings (from attack_scan / attack_report)
        target: the assessed target (enables the in-scope readiness check)
        platform: hackerone | bugcrowd
        known_signatures: comma-separated `vuln_class|point` signatures already submitted (dup check)
    """
    try:
        items = json.loads(findings) if findings else []
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "findings must be a JSON array"})
    gate = _AuthGate()
    known = [s.strip() for s in known_signatures.split(",") if s.strip()]
    from hydra.attack.triage import triage_finding as _triage
    rows = [_triage(f, target=target, platform=platform, gate=gate, known_signatures=known)
            for f in items]
    ready = [r for r in rows if r["readiness"]["ready"]]
    return json.dumps({"target": target, "platform": platform, "triaged": len(rows),
                       "ready_to_submit": len(ready), "results": rows, "advisory": True}, indent=2)


@mcp.tool()
def attack_correlate(findings: str) -> str:
    """Correlate & dedup findings (attack section): merges findings sharing a root cause
    `(vuln_class, normalized endpoint)` — so the same bug seen via multiple params/endpoints becomes one
    finding carrying every instance. Pure/advisory.

    Args:
        findings: JSON array of findings
    """
    try:
        items = json.loads(findings) if findings else []
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "findings must be a JSON array"})
    return json.dumps(_FindingCorrelator().merge(items), indent=2)


@mcp.tool()
def attack_auth_session(target: str, check: str = "csrf", session: str = "",
                        csrf_field: str = "", csrf_header: str = "", method: str = "POST",
                        body: str = "", email_field: str = "email", email: str = "victim@example.com",
                        evil_host: str = "evil.example.com", json_body: bool = False,
                        rate_per_sec: float = 1.0) -> str:
    """Authorization-gated auth/session test (attack section): csrf | cookies | reset_poison.
    CSRF replays a state-changing request without/with-bad token and cross-origin; cookies audits
    Set-Cookie security attributes; reset_poison tampers Host/X-Forwarded-Host on the reset flow.
    Deny-by-default; PoC-only.

    Args:
        target: in-scope url (the state-changing endpoint / reset endpoint / any page that sets cookies)
        check: csrf | cookies | reset_poison
        session: JSON identity (CSRF needs an authenticated session)
        csrf_field: anti-CSRF body field name (CSRF)
        csrf_header: anti-CSRF header name (CSRF)
        method: state-changing method for CSRF (default POST)
        body: request body for CSRF
        email_field/email: reset-flow field + the address to request (reset_poison)
        evil_host: attacker host to inject into Host headers (reset_poison)
        json_body: send reset body as JSON
        rate_per_sec: max requests/sec (clamped 0.1–5.0)
    """
    gate = _AuthGate()
    ex = _HttpExecutor(gate=gate, rate_per_sec=max(0.1, min(rate_per_sec, 5.0)))
    try:
        sess = _parse_session(session, "auth") if session else None
    except (ValueError, json.JSONDecodeError):
        return json.dumps({"error": "session must be a JSON object"})
    if check == "csrf":
        req = {"method": method, "url": target, "headers": {}, "body": body}
        if json_body:
            req["headers"]["Content-Type"] = "application/json"
        res = _CSRFTester(gate=gate, executor=ex).test(req, csrf_field=csrf_field,
                                                       csrf_header=csrf_header, session=sess)
    elif check == "cookies":
        d = gate.authorize(target, "active_recon")
        if not d.authorized:
            return json.dumps({"authorized": False, "reason": d.reason})
        resp = ex({"method": "GET", "url": target, "headers": {}})
        res = _CookieAuditor().audit(resp.get("set_cookie", []))
        res["target"] = target
    elif check == "reset_poison":
        res = _PasswordResetPoisoning(gate=gate, executor=ex).test(
            target, email_field=email_field, email=email, evil_host=evil_host, json_body=json_body)
    else:
        return json.dumps({"error": f"unknown check '{check}'",
                           "known": ["csrf", "cookies", "reset_poison"]})
    return json.dumps(res, indent=2)


@mcp.tool()
def attack_tech_plan(fingerprint: str, platform: str = "hackerone") -> str:
    """Technology-fingerprint attack planner (attack section): given a stack fingerprint (techs from
    `whatweb_detect` / headers), recommends WHICH vuln classes are worth testing (and why). Pass the
    same fingerprint to `attack_scan` to float stack-relevant payloads to the front. Pure/advisory.

    Args:
        fingerprint: comma/space-separated techs (e.g. "wordpress php mysql nginx")
        platform: hackerone | bugcrowd (reserved for severity context)
    """
    return json.dumps(_FingerprintSelector().plan(fingerprint), indent=2)


@mcp.tool()
def ingest_report(path: str = "", text: str = "", source_url: str = "",
                  target: str = "", title: str = "") -> str:
    """Report Intelligence: distill a disclosed report/writeup into the knowledge graph.

    Extracts reusable attacker knowledge (root cause, trust-boundary failure,
    exploitation sequence, escalation, impact, attacker assumptions), assigns a
    deterministic 1-10 `learning_score`, and writes cross-linked canonical
    `report` + `intel` wiki pages. Offline-first; only `report`/`intel` pages are
    ever created (no findings/patterns/chains); missing technique/pattern links
    are recorded as `unresolved_references`, never auto-created.

    Args:
        path: path to a local report file (read offline)
        text: raw report content (alternative to path)
        source_url: original disclosure URL (for provenance / slug identity)
        target: program/asset slug the report concerns (e.g. "vk")
        title: report title (used for the deterministic page slug)
    """
    if (g := _kb_guard()):
        return g
    if not (path or text):
        return json.dumps({"success": False, "error": "provide 'path' or 'text'"})
    src = ReportSource(path=path, text=text, source_url=source_url, target=target, title=title)
    try:
        extracted = ReportIntelligencePipeline(WikiStore()).ingest(src)
    except FileNotFoundError:
        return json.dumps({"success": False, "error": f"report file not found: {path}"})
    return json.dumps({"success": True, **extracted.to_dict()}, indent=2)


@mcp.tool()
def report_lookup(slug: str) -> str:
    """Look up an ingested report page: metadata, learning_score, and links."""
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    page = store.get(slug, _NodeType.REPORT)
    if page is None:
        return json.dumps({"success": False, "error": f"no report page for: {slug}"})
    return json.dumps({
        "success": True, "slug": slug, "path": str(page.path),
        "learning_score": page.meta.get("learning_score"),
        "learning_score_rationale": page.meta.get("learning_score_rationale"),
        "vuln_class": page.meta.get("vuln_class"),
        "severity": page.meta.get("severity"),
        "unresolved_references": page.meta.get("unresolved_references", []),
        "links": [s for s in page.links],
    }, indent=2)


@mcp.tool()
def list_reports(min_learning_score: int = 0) -> str:
    """List ingested report pages ranked by learning_score (high-value learning first).

    Args:
        min_learning_score: only include reports scoring at or above this (0-10)
    """
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    rows = []
    for page in store.iter_pages(_NodeType.REPORT):
        score = page.meta.get("learning_score", 0)
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        if score >= min_learning_score:
            rows.append({"slug": page.slug, "learning_score": score,
                         "vuln_class": page.meta.get("vuln_class"),
                         "severity": page.meta.get("severity")})
    # Deterministic order: highest score first, ties broken by slug.
    rows.sort(key=lambda r: (-r["learning_score"], r["slug"]))
    return json.dumps({"count": len(rows), "reports": rows}, indent=2)


def _policy(online: bool):
    """Build an ExecutionPolicy. Online keys come from HYDRA_SOURCE_KEYS (comma-separated)."""
    if not online:
        return ExecutionPolicy.offline()
    keys = {k.strip() for k in os.environ.get("HYDRA_SOURCE_KEYS", "").split(",") if k.strip()}
    return ExecutionPolicy.online(available_keys=keys)


# ══════════════════════════════════════════════
#  SERVER ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HYDRA MCP Security Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"], default="stdio",
        help="MCP transport: stdio (local) or sse (HTTP for remote clients)"
    )
    parser.add_argument("--port", type=int, default=8900, help="Port for SSE transport")
    args = parser.parse_args()

    print("[HYDRA] MCP Security Server starting...", file=sys.stderr)
    print(f"[HYDRA] Transport: {args.transport}", file=sys.stderr)
    print("[HYDRA] Tools available for any MCP-compatible AI agent", file=sys.stderr)

    if args.transport == "sse":
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        _install_threaded_stdio_transport()
        mcp.run(transport="stdio")
