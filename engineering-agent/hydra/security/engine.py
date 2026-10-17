"""Security lifecycle, scope gate and tool execution boundary."""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from hydra.mcp.tool_server import MCPToolServer
from hydra.mcp.client import MCPClient


from hydra.security.discovery import DiscoveryWorkflows
from hydra.security.local import LocalWorkflows
from hydra.security.investigation import InvestigationWorkflows
from hydra.security.swarm import SwarmWorkflows
from hydra.security.results import ResultPipeline

logger = logging.getLogger("hydra.security")


class HydraEngine(
    DiscoveryWorkflows,
    LocalWorkflows,
    InvestigationWorkflows,
    SwarmWorkflows,
    ResultPipeline,
):
    """
    Lightweight engine that initialises only what's needed and runs
    a workflow against a target.  Designed to work NOW with zero
    external services (no Redis, no ChromaDB, no AI keys needed).
    """

    LOCAL_WORKFLOWS = {"code_review", "web3_audit"}

    WORKFLOW_COVERAGE = {
        "quick_recon": [
            "reconnaissance",
            "asset-discovery",
            "technology-identification",
            "injection-classes",
        ],
        "full_bounty": [
            "reconnaissance",
            "asset-discovery",
            "technology-identification",
            "endpoint-discovery",
            "injection-classes",
            "xss",
            "path-traversal",
            "information-disclosure",
        ],
        "api_only": [
            "reconnaissance",
            "api-security",
            "http-method-handling",
            "parameter-manipulation",
            "injection-classes",
        ],
        "blackbox": [
            "reconnaissance",
            "asset-discovery",
            "endpoint-discovery",
            "injection-classes",
        ],
        # Autonomous per-vuln-class hunt (HuntEngine). Phase-1 nuclei is always
        # on; the injection-family probes only actually fire with --hunt-active.
        # Areas a nuclei-only run does not truly evaluate stay pending, honestly.
        "hunt": [
            "injection-classes",
            "ssrf",
            "path-traversal",
            "xss",
            "information-disclosure",
        ],
        # Human-gated single-finding confirmation (ConfirmationEngine). Raises
        # evidence with benign proofs only; it does not survey new surface, so it
        # honestly claims just the areas it re-tests (injection/ssrf/xss, plus
        # admin-functionality reachability for the SAP CVE-2025-31324 endpoint,
        # access-control for the Astro CVE-2025-64525 forwarded-origin bypass,
        # file-access-control for the Vite CVE-2025-30208 server.fs.deny bypass,
        # cache-poisoning for the Next.js CVE-2025-57752 image-optimizer
        # cache-key confusion, and service-exposure for the ingress-nginx
        # CVE-2025-1974 admission-controller reachability precondition).
        "confirm": [
            "injection-classes",
            "ssrf",
            "xss",
            "admin-functionality",
            "access-control",
            "file-access-control",
            "cache-poisoning",
            "service-exposure",
        ],
        # Multi-agent swarm (Coordinator + pipeline agents). The recon/analysis
        # phases genuinely cover discovery + nuclei-grade injection detection; the
        # hypothesis/validation phases reason over those results rather than
        # surveying new surface, so coverage stays honestly scoped to what the
        # agents actually touch.
        "swarm": [
            "reconnaissance",
            "asset-discovery",
            "technology-identification",
            "endpoint-discovery",
            "injection-classes",
        ],
    }

    def __init__(
        self,
        target: str,
        workflow: str = "quick_recon",
        output_dir: str = "output",
        timeout: int = 120,
        ml_filter: bool = False,
        ml_threshold: float = 0.5,
        learn: bool = True,
        auto_label: bool = True,
        scope_url: str = "",
        scope_file: str = "",
        scope_token: str = "",
        allow_no_scope: bool = False,
        hunt_class: str = "auto",
        hunt_mode: str = "normal",
        hunt_active: bool = False,
        confirm_param: str = "",
        confirm_class: str = "",
        oob_callback: str = "",
        confirm_auth_header: str = "",
        no_ai: bool = False,
    ):
        self.target = target
        self.workflow_name = workflow
        self.output_dir = Path(output_dir) / self._safe_dir(target)
        self.timeout = timeout
        self.ml_filter = ml_filter
        self.ml_threshold = ml_threshold
        self.learn = learn
        self.auto_label = auto_label
        self.scope_url = scope_url
        self.scope_file = scope_file
        self.scope_token = scope_token
        self.allow_no_scope = allow_no_scope
        self.hunt_class = hunt_class
        self.hunt_mode = hunt_mode
        self.hunt_active = hunt_active
        self.confirm_param = confirm_param
        self.confirm_class = confirm_class
        self.oob_callback = oob_callback
        self.confirm_auth_header = confirm_auth_header
        self.no_ai = no_ai
        self.tool_results: List[Dict[str, Any]] = []
        self._scope = None  # ScopePolicyEngine once loaded
        self._blocked: List[str] = []  # targets refused by scope
        self.scan_id = f"{self._safe_dir(target)}:{workflow}:{int(time.time())}"
        self.tool_server: Optional[MCPToolServer] = None
        self.mcp: Optional[MCPClient] = None
        self.findings: List[Dict[str, Any]] = []
        self.recon_data: Dict[str, Any] = {}
        self._start_time = 0.0

    @staticmethod
    def _origin(url: str) -> str:
        """Reduce a URL to scheme://host (drops path/query) for graph node ids."""
        from urllib.parse import urlparse

        u = (url or "").strip()
        if "://" not in u:
            return u.split("/")[0]
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}" if p.netloc else u

    @staticmethod
    def _safe_dir(target: str) -> str:
        import re

        name = target.replace("https://", "").replace("http://", "")
        name = re.sub(r"[^\w.\-]", "_", name).strip(". ")
        return name[:160] or "target"

    async def init(self):
        """Initialise only the MCP tool server (fast, no external deps)."""
        self._start_time = time.time()

        # Output dirs
        for sub in ["recon", "scans", "reports", "evidence", "logs"]:
            (self.output_dir / sub).mkdir(parents=True, exist_ok=True)

        # Scope enforcement — load authorized scope before any tool runs.
        await self._load_scope()

        # Tool server
        self.tool_server = MCPToolServer()
        if self._scope and self._scope.is_loaded:
            self.tool_server.set_scope_engine(self._scope)
        await self.tool_server.initialize()
        self.mcp = MCPClient(tool_server=self.tool_server)
        logger.info("[bold green]✅ HYDRA engine ready[/bold green]")

    async def _load_scope(self):
        """Load the authorized scope from a URL or JSON file, if provided."""
        from hydra.scope import ScopePolicyEngine

        self._scope = ScopePolicyEngine()
        try:
            if self.scope_file:
                data = json.loads(Path(self.scope_file).read_text(encoding="utf-8"))
                self._scope.load_from_dict(data)
            elif self.scope_url:
                await self._scope.load_from_url(
                    self.scope_url, api_token=self.scope_token
                )
        except Exception as e:
            logger.error(f"[red]Failed to load scope:[/] {e}")
            self._scope = ScopePolicyEngine()  # stays unloaded → fail-closed

    def _scope_ok(self, target: str) -> bool:
        """Return True if `target` may be tested under the loaded scope.

        Fail-closed: if no scope is loaded and the operator did not pass
        --allow-no-scope, everything is refused.
        """
        if self._scope and self._scope.is_loaded:
            res = self._scope.validate_target(target)
            if not res.allowed:
                if target not in self._blocked:
                    self._blocked.append(target)
                    logger.warning(
                        f"  🚫 [red]OUT OF SCOPE[/] — {target}: {res.reason}"
                    )
                return False
            return True
        # No scope loaded.
        return bool(self.allow_no_scope)

    async def run(self) -> Dict[str, Any]:
        """Run the selected workflow and return a summary."""
        logger.info(f"[bold cyan]🎯 Target:[/] {self.target}")
        logger.info(f"[bold cyan]📋 Workflow:[/] {self.workflow_name}")

        # ── Scope gate ──────────────────────────
        local_workflow = self.workflow_name in self.LOCAL_WORKFLOWS
        if local_workflow and not Path(self.target).exists():
            return {
                "error": "invalid_target",
                "target": self.target,
                "message": f"Local target does not exist: {self.target}",
            }
        if local_workflow:
            logger.info(
                "[dim]🔒 Local file-analysis workflow — scope not applicable[/dim]"
            )
        elif self._scope and self._scope.is_loaded:
            logger.info("[bold green]🔒 Scope enforcement ACTIVE[/bold green]")
        elif self.allow_no_scope:
            logger.warning(
                "[yellow]⚠️  Running WITHOUT scope enforcement "
                "(--allow-no-scope). You assert you are authorized "
                "to test this target.[/yellow]"
            )
        else:
            logger.error(
                "[bold red]🚫 REFUSING TO SCAN — no scope loaded.[/bold red]\n"
                "   HYDRA is fail-closed: load an authorized scope with "
                "--scope-file <json> or --scope-url <program>,\n"
                "   or pass --allow-no-scope to assert authorization explicitly."
            )
            return {
                "error": "no_scope",
                "message": "No authorized scope loaded (fail-closed). "
                "Use --scope-file/--scope-url or --allow-no-scope.",
            }

        if not local_workflow and not self._scope_ok(self.target):
            return {
                "error": "out_of_scope",
                "target": self.target,
                "message": f"Primary target '{self.target}' is not in the "
                f"authorized scope.",
            }

        # Dynamic workflow dispatch
        runner = getattr(self, f"_wf_{self.workflow_name}", None)
        if runner is None:
            logger.error(f"Unknown workflow: {self.workflow_name}")
            return {"error": f"Unknown workflow: {self.workflow_name}"}

        await runner()

        # Track this workflow run inside the continuous-engagement state machine
        # (inventory + checklist + coverage audit per the red-team doctrine).
        engagement_state = self._track_engagement()

        elapsed = round(time.time() - self._start_time, 1)
        summary = {
            "target": self.target,
            "workflow": self.workflow_name,
            "elapsed_s": elapsed,
            "recon": {
                k: len(v) if isinstance(v, list) else v
                for k, v in self.recon_data.items()
            },
            "findings_count": len(self.findings),
            "findings": self.findings,
            "engagement": engagement_state,
            "output_dir": str(self.output_dir),
        }
        # Learning loop: record findings + auto-label from validation
        if self.learn:
            await self._record_and_label()
            summary["scan_id"] = self.scan_id

        # Optional ML pass over findings
        if self.ml_filter and not self.no_ai:
            self._apply_ml()
            summary["findings"] = self.findings
            summary["findings_count"] = len(self.findings)

        # Context enrichment: match each finding against the corpus of real
        # disclosed write-ups (semantic memory) so the report carries links to
        # comparable known cases. This is what makes the ingested reports pay off.
        if not self.no_ai:
            await self._enrich_from_memory()
        summary["findings"] = self.findings

        failures = [r for r in self.tool_results if not r.get("success")]
        summary["tool_failures"] = failures
        summary["status"] = "partial" if failures else "completed"
        if self.tool_results and len(failures) == len(self.tool_results):
            summary.update(
                status="failed",
                error="tool_execution_failed",
                message="All attempted tools failed. Check --check-tools and tool_failures in summary.json.",
            )

        self._save_json("reports/summary.json", summary)

        # Generate submission-ready reports (Markdown + HTML + JSON)
        summary["reports"] = self._generate_reports()
        return summary

    CODE_REVIEW_RULES = [
        (
            "hardcoded_secret",
            "high",
            r"(?i)(api[_-]?key|secret|password|passwd|token|aws_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "Possible hardcoded credential/secret",
        ),
        (
            "private_key",
            "critical",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            "Embedded private key",
        ),
        (
            "shell_injection",
            "high",
            r"(?i)(subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True|os\.system\()",
            "Shell command execution — risk of command injection",
        ),
        (
            "dangerous_eval",
            "high",
            r"\b(eval|exec)\s*\(",
            "Use of eval/exec on dynamic input",
        ),
        (
            "sql_string_concat",
            "high",
            r"(?i)(execute|executemany)\s*\(\s*[f\"'].*(SELECT|INSERT|UPDATE|DELETE).*[%+].*\)",
            "SQL built via string formatting — risk of SQL injection",
        ),
        (
            "weak_hash",
            "medium",
            r"(?i)hashlib\.(md5|sha1)\s*\(",
            "Weak hashing algorithm (MD5/SHA1)",
        ),
        (
            "insecure_random",
            "low",
            r"\brandom\.(random|randint|choice)\s*\(",
            "Non-cryptographic RNG — do not use for secrets/tokens",
        ),
        (
            "tls_verify_disabled",
            "high",
            r"(?i)(verify\s*=\s*False|CERT_NONE|InsecureRequestWarning)",
            "TLS certificate verification disabled",
        ),
        (
            "debug_enabled",
            "low",
            r"(?i)debug\s*=\s*True",
            "Debug mode enabled — leaks stack traces in production",
        ),
    ]

    CODE_REVIEW_EXTS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rb",
        ".php",
        ".java",
        ".cs",
        ".c",
        ".cpp",
        ".sh",
        ".yml",
        ".yaml",
        ".env",
        ".ini",
        ".conf",
    }

    async def _run_tool(
        self, tool_name: str, params: Dict[str, Any], stdin: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute a tool via the MCP client, log result, save artifact."""
        assert self.mcp is not None

        # ── Per-target scope enforcement ────────
        # Validate the tool's target (and any stdin host list) before it runs,
        # so subdomains/hosts discovered mid-scan can't drag us out of scope.
        # Local file-analysis workflows are exempt (no network target).
        tgt = params.get("target", self.target)
        if self.workflow_name not in self.LOCAL_WORKFLOWS and not self._scope_ok(tgt):
            return {
                "success": False,
                "tool_used": tool_name,
                "error": f"blocked: '{tgt}' out of scope",
                "output": "",
                "elapsed": 0,
            }
        if stdin:
            allowed = [
                h
                for h in stdin.splitlines()
                if not h.strip() or self._scope_ok(h.strip())
            ]
            stdin = "\n".join(allowed)
            params["_stdin"] = stdin

        result = await self.mcp.execute_tool(tool_name, params, timeout=self.timeout)
        self.tool_results.append(
            {
                "tool": tool_name,
                "success": result.get("success", False),
                "error": result.get("error", ""),
            }
        )
        success = result.get("success", False)
        tool_used = result.get("tool_used", tool_name)
        elapsed = result.get("elapsed", 0)
        if success:
            logger.info(f"  ✅ {tool_used} completed in {elapsed}s")
        else:
            err = result.get("error", "unknown")
            logger.warning(f"  ⚠️  {tool_used} failed: {err}")
        # Save raw output
        self._save_text(f"logs/{tool_name}_raw.txt", result.get("output", ""))
        return result

    @staticmethod
    def _lines(result: Dict) -> List[str]:
        output = result.get("output", "")
        return (
            [l.strip() for l in output.strip().split("\n") if l.strip()]
            if output
            else []
        )

    @staticmethod
    def _parse_nuclei(output: str) -> List[Dict]:
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(
                    {
                        "name": data.get("info", {}).get(
                            "name", data.get("template-id", "")
                        ),
                        "severity": data.get("info", {}).get("severity", "info"),
                        "template_id": data.get("template-id", ""),
                        "matched_at": data.get("matched-at", data.get("host", "")),
                        "type": data.get("type", ""),
                        "evidence": data.get(
                            "extracted-results", data.get("matcher-name", "")
                        ),
                    }
                )
            except json.JSONDecodeError:
                # Non-JSON line (e.g. [template-id] [severity] host)
                if "[" in line:
                    findings.append({"name": line, "severity": "info", "raw": True})
        return findings

    def _save_json(self, rel_path: str, data: Any):
        p = self.output_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _save_text(self, rel_path: str, text: str):
        p = self.output_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def _save_lines(self, rel_path: str, lines: List[str]):
        self._save_text(rel_path, "\n".join(lines))
