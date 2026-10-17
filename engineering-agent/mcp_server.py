#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA MCP Server — Security Tool Execution Layer           ║
║  Compatible with: Claude Code, Cursor, Cline, Windsurf      ║
║  Usage: Add to your AI coding agent's MCP config             ║
╚══════════════════════════════════════════════════════════════╝

This MCP server gives any AI coding agent direct access to
real security tools via the Model Context Protocol.

Supported AI agents:
  - Claude Code:  auto-detected via .mcp.json
  - Cursor:       add to .cursor/mcp.json
  - Cline:        add to cline_mcp_settings.json
  - Windsurf:     add to ~/.windsurf/mcp.json
  - Any MCP-compatible client

All tools are REAL — executed via subprocess. No mocking.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────
#  Server Setup
# ──────────────────────────────────────────────

mcp = FastMCP(
    "hydra-security",
)

# Paths
BASE_DIR = Path(__file__).parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
RESULTS_DIR = BASE_DIR / "results"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
LEARNING_DB = DATA_DIR / "learning.db"

for d in [WORDLISTS_DIR, RESULTS_DIR, REPORTS_DIR, DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────
#  Scope enforcement + rate limiting (fail-closed)
# ──────────────────────────────────────────────
#
# This root server historically ran fail-OPEN: any MCP client could launch
# offensive tools against ANY target with no scope check and no rate limit —
# unlike HydraEngine, which is fail-closed. We wire in the SAME gate here so
# that simply launching this server does not hand out unauthorized scanning.
#
# Scope is loaded once at import from the environment (so it applies no matter
# which MCP client spawns the process):
#   HYDRA_SCOPE_FILE   — path to a scope JSON  → load_from_dict
#   HYDRA_SCOPE_URL    — bug-bounty program URL → load_from_url
#   HYDRA_SCOPE_TOKEN  — API token for the program platform (optional)
#   HYDRA_ALLOW_NO_SCOPE — "1"/"true" to assert authorization with no scope
#   HYDRA_ENFORCE_SCOPE  — "false" disables enforcement globally (config)

try:
    from hydra.scope import ScopePolicyEngine
    from hydra.config import get_config
except Exception:  # pragma: no cover - hydra may not be on sys.path yet
    try:
        sys.path.insert(0, str(BASE_DIR))
        from hydra.scope import ScopePolicyEngine
        from hydra.config import get_config
    except Exception as _imp_err:
        ScopePolicyEngine = None
        get_config = None
        print(f"[HYDRA] scope module unavailable ({_imp_err}); tools fail-closed "
              f"unless HYDRA_ALLOW_NO_SCOPE=1", file=sys.stderr)


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


# Rate-limit / concurrency limits (mirror SandboxConfig; safe defaults if hydra
# is unavailable). max_concurrent_tools caps parallel subprocesses; the
# min-interval throttle caps how fast tools are launched.
_MAX_CONCURRENT, _RPS, _ENFORCE_DISABLED = 5, 50, False
if get_config is not None:
    try:
        _cfg = get_config()
        _MAX_CONCURRENT = max(1, int(_cfg.sandbox.max_concurrent_tools))
        _RPS = max(1, int(_cfg.sandbox.max_requests_per_second))
        _ENFORCE_DISABLED = not _cfg.scope.enforce_scope
    except Exception:
        pass

_TOOL_SEMAPHORE = threading.Semaphore(_MAX_CONCURRENT)
_RATE_LOCK = threading.Lock()
_MIN_INTERVAL = 1.0 / float(_RPS)
_LAST_LAUNCH = [0.0]

# Explicit operator override: run without a loaded scope. Either the env flag
# or globally disabling enforcement asserts "I am authorized to test this."
_ALLOW_NO_SCOPE = _env_true("HYDRA_ALLOW_NO_SCOPE") or _ENFORCE_DISABLED
_SCOPE = None  # ScopePolicyEngine once loaded


def _load_scope_from_env() -> None:
    """Load the authorized scope from the environment (fail-closed on error)."""
    global _SCOPE
    if ScopePolicyEngine is None:
        return
    scope_file = os.getenv("HYDRA_SCOPE_FILE", "").strip()
    scope_url = os.getenv("HYDRA_SCOPE_URL", "").strip()
    scope_token = os.getenv("HYDRA_SCOPE_TOKEN", "").strip()
    eng = ScopePolicyEngine()
    try:
        if scope_file:
            data = json.loads(Path(scope_file).read_text(encoding="utf-8"))
            eng.load_from_dict(data)
        elif scope_url:
            asyncio.run(eng.load_from_url(scope_url, api_token=scope_token))
    except Exception as e:
        print(f"[HYDRA] Failed to load scope: {e} — staying fail-closed",
              file=sys.stderr)
        eng = ScopePolicyEngine()  # unloaded → fail-closed
    _SCOPE = eng


_load_scope_from_env()


def _no_scope_error(target: str) -> dict:
    return {
        "success": False, "blocked_by_scope": True, "target": target, "output": "",
        "error": ("No authorized scope loaded (fail-closed). Set HYDRA_SCOPE_FILE="
                  "<json> or HYDRA_SCOPE_URL=<program> (optionally HYDRA_SCOPE_TOKEN), "
                  "or HYDRA_ALLOW_NO_SCOPE=1 to assert you are authorized."),
    }


def _scope_gate(target: str, tool_name: str = "") -> Optional[dict]:
    """Return an error dict if `target` may NOT be scanned, else None.

    Fail-closed, mirroring HydraEngine: with a scope loaded the target must
    validate (and, via validate_tool_execution, must not hit forbidden testing
    types); with no scope loaded everything is refused unless the operator set
    HYDRA_ALLOW_NO_SCOPE / disabled enforcement.
    """
    target = (target or "").strip()
    if not target:
        return {"success": False, "error": "Empty target", "output": ""}
    if _SCOPE is not None and _SCOPE.is_loaded:
        res = (_SCOPE.validate_tool_execution(tool_name, target)
               if tool_name else _SCOPE.validate_target(target))
        if not res.allowed:
            print(f"[HYDRA] 🚫 BLOCKED by scope: {tool_name or 'tool'} → {target}: "
                  f"{res.reason}", file=sys.stderr)
            return {"success": False, "blocked_by_scope": True, "target": target,
                    "output": "", "error": f"Scope violation: {res.reason}",
                    "policy_violations": res.policy_violations}
        return None
    return None if _ALLOW_NO_SCOPE else _no_scope_error(target)


def _scope_filter(targets_text: str, tool_name: str = "") -> tuple:
    """Filter newline-separated targets to those in scope.

    Returns (allowed_lines, error_dict_or_None). Fail-closed like `_scope_gate`:
    drops out-of-scope hosts; if none survive (or no scope is loaded and no
    override), returns an error dict instead.
    """
    lines = [l.strip() for l in (targets_text or "").splitlines() if l.strip()]
    if _SCOPE is not None and _SCOPE.is_loaded:
        allowed = [l for l in lines
                   if _SCOPE.validate_tool_execution(tool_name, l).allowed]
        if not allowed:
            return [], {"success": False, "blocked_by_scope": True, "output": "",
                        "error": "No provided targets are in the authorized scope."}
        return allowed, None
    if _ALLOW_NO_SCOPE:
        return lines, None
    return [], _no_scope_error("<targets>")


def _throttle() -> None:
    """Coarse launch-rate limiter shared across tool-worker threads."""
    with _RATE_LOCK:
        wait = _MIN_INTERVAL - (time.time() - _LAST_LAUNCH[0])
        if wait > 0:
            time.sleep(wait)
        _LAST_LAUNCH[0] = time.time()


def _run(cmd: List[str], timeout: int = 120, stdin_data: Optional[str] = None) -> dict:
    """Execute a real system tool via subprocess. No mocking."""
    binary = cmd[0]
    path = shutil.which(binary)
    if not path:
        return {
            "success": False,
            "error": f"Tool '{binary}' not installed. Install it first.",
            "output": "",
        }

    print(f"[HYDRA] Running: {' '.join(cmd)}", file=sys.stderr)

    # Rate limit / concurrency: cap parallel subprocesses and launch cadence.
    with _TOOL_SEMAPHORE:
        _throttle()
        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data,
            )
            elapsed = round(time.time() - start, 2)
            return {
                "success": proc.returncode == 0,
                "output": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
                "elapsed_seconds": elapsed,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Timeout after {timeout}s", "output": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "output": ""}


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
    blocked = _scope_gate(domain, "subfinder")
    if blocked:
        return json.dumps(blocked, indent=2)
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    result = _run(cmd, timeout=180)
    if result["success"]:
        subs = [l.strip() for l in result["output"].strip().split("\n") if l.strip()]
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
    blocked = _scope_gate(domain, "amass")
    if blocked:
        return json.dumps(blocked, indent=2)
    cmd = ["amass", "enum"]
    if passive:
        cmd.append("-passive")
    cmd.extend(["-d", domain])
    result = _run(cmd, timeout=300)
    if result["success"]:
        subs = [l.strip() for l in result["output"].strip().split("\n") if l.strip()]
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
    allowed, blocked = _scope_filter(targets, "httpx")
    if blocked:
        return json.dumps(blocked, indent=2)
    targets = "\n".join(allowed)
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
def katana_crawl(target: str, depth: int = 3, js_crawl: bool = False) -> str:
    """
    Crawl a target website to discover endpoints, URLs, and JS files.
    Uses Katana web crawler.

    Args:
        target: Target URL (e.g., "https://example.com")
        depth: Crawl depth (1-5)
        js_crawl: Also crawl JavaScript files for endpoints
    """
    blocked = _scope_gate(target, "katana")
    if blocked:
        return json.dumps(blocked, indent=2)
    cmd = ["katana", "-u", target, "-silent", "-d", str(min(depth, 5))]
    if js_crawl:
        cmd.append("-jc")
    result = _run(cmd, timeout=180)
    if result["success"]:
        urls = [l.strip() for l in result["output"].strip().split("\n") if l.strip()]
        return json.dumps({"endpoints": urls, "count": len(urls)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def gau_urls(domain: str) -> str:
    """
    Fetch known URLs for a domain from Wayback Machine, Common Crawl,
    and other sources using gau (Get All URLs).

    Args:
        domain: Target domain (e.g., "example.com")
    """
    blocked = _scope_gate(domain, "gau")
    if blocked:
        return json.dumps(blocked, indent=2)
    cmd = ["gau", domain]
    result = _run(cmd, timeout=120)
    if result["success"]:
        urls = [l.strip() for l in result["output"].strip().split("\n") if l.strip()]
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
    blocked = _scope_gate(target, "nuclei")
    if blocked:
        return json.dumps(blocked, indent=2)
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
    allowed, blocked = _scope_filter(targets, "nuclei")
    if blocked:
        return json.dumps(blocked, indent=2)
    targets = "\n".join(allowed)
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
    blocked = _scope_gate(url, "ffuf")
    if blocked:
        return json.dumps(blocked, indent=2)
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
    blocked = _scope_gate(url, "dirsearch")
    if blocked:
        return json.dumps(blocked, indent=2)
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads), "-q",
           "--output-formats=json"]
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
    blocked = _scope_gate(target, "whatweb")
    if blocked:
        return json.dumps(blocked, indent=2)
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
    blocked = _scope_gate(target, "wafw00f")
    if blocked:
        return json.dumps(blocked, indent=2)
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
    blocked = _scope_gate(target, "nmap")
    if blocked:
        return json.dumps(blocked, indent=2)
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
    blocked = _scope_gate(domain, "subfinder")
    if blocked:
        return json.dumps(blocked, indent=2)
    results = {"domain": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    # Step 1: Subdomain enumeration
    print("[HYDRA] Step 1/3: Subdomain enumeration...", file=sys.stderr)
    sub_result = _run(["subfinder", "-d", domain, "-silent"], timeout=180)
    subdomains = []
    if sub_result["success"]:
        subdomains = [l.strip() for l in sub_result["output"].strip().split("\n")
                      if l.strip()]
    results["subdomains"] = subdomains
    results["subdomain_count"] = len(subdomains)

    # Step 2: HTTP probe (only subdomains that are themselves in scope —
    # enumeration can surface third-party/out-of-scope hosts we must not probe).
    if subdomains:
        in_scope_subs, _sf_block = _scope_filter("\n".join(subdomains), "httpx")
        if _sf_block:
            in_scope_subs = []  # scope loaded but nothing enumerated is in scope
        results["subdomains_in_scope"] = len(in_scope_subs)
        if in_scope_subs:
            print("[HYDRA] Step 2/3: HTTP probing...", file=sys.stderr)
            probe_input = "\n".join(in_scope_subs)
            probe_result = _run(["httpx", "-silent", "-sc", "-title"],
                               timeout=120, stdin_data=probe_input)
            live_hosts = []
            if probe_result["success"]:
                live_hosts = [l.strip() for l in probe_result["output"].strip().split("\n")
                             if l.strip()]
            results["live_hosts"] = live_hosts
            results["live_count"] = len(live_hosts)
        else:
            results["live_hosts"] = []
            results["live_count"] = 0
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
        "whatweb": "Tech fingerprinting",
        "wafw00f": "WAF detection",
        "nmap": "Network scanning",
        "dirsearch": "Directory brute-forcing",
    }

    status = {}
    available = 0
    for tool, desc in tools.items():
        path = shutil.which(tool)
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
            f"# HYDRA Security Assessment Report",
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
#  SERVER ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    print("[HYDRA] MCP Security Server starting...", file=sys.stderr)
    print("[HYDRA] Tools available for any MCP-compatible AI agent", file=sys.stderr)
    mcp.run(transport="stdio")
