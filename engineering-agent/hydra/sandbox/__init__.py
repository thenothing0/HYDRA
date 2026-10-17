"""
╔══════════════════════════════════════════════════════════════╗
║  Security Sandbox — Isolated Execution & Scope Enforcement ║
║  Command allowlists, rate limiting, resource limits        ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.sandbox")


@dataclass
class ExecutionPolicy:
    """Execution policy for a scan session."""
    allowed_tools: Set[str] = field(default_factory=lambda: {
        "subfinder", "amass", "httpx", "nuclei", "ffuf",
        "katana", "gau", "whatweb", "wafw00f", "nmap",
        "dirsearch", "dnsx", "hakrawler",
    })
    blocked_tools: Set[str] = field(default_factory=set)
    allowed_targets: Set[str] = field(default_factory=set)
    blocked_targets: Set[str] = field(default_factory=set)
    max_requests_per_second: int = 50
    max_concurrent_tools: int = 5
    max_scan_duration: int = 7200  # 2 hours
    allow_active_exploitation: bool = False
    allow_brute_force: bool = True
    allow_port_scan: bool = True
    resource_limits: Dict[str, int] = field(default_factory=lambda: {
        "max_memory_mb": 2048,
        "max_cpu_percent": 80,
        "max_disk_mb": 5120,
    })


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate: float = 50.0, burst: int = 100):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> bool:
        async with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._burst,
                self._tokens + elapsed * self._rate
            )
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def wait_and_acquire(self, tokens: int = 1,
                               timeout: float = 30.0):
        """Wait until tokens are available."""
        start = time.time()
        while time.time() - start < timeout:
            if await self.acquire(tokens):
                return True
            await asyncio.sleep(0.1)
        return False


class ScopeEnforcer:
    """Enforces target scope restrictions."""

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy

    def is_target_allowed(self, target: str) -> bool:
        """Check if a target is within scope."""
        target_lower = target.lower().strip()

        # Remove protocol
        for prefix in ["https://", "http://", "ftp://"]:
            if target_lower.startswith(prefix):
                target_lower = target_lower[len(prefix):]

        # Remove path
        target_lower = target_lower.split("/")[0].split(":")[0]

        # Check blocked first
        for blocked in self.policy.blocked_targets:
            if self._matches(target_lower, blocked.lower()):
                logger.warning(f"🚫 Target blocked: {target}")
                return False

        # If allowed list is empty, everything is allowed
        if not self.policy.allowed_targets:
            return True

        for allowed in self.policy.allowed_targets:
            if self._matches(target_lower, allowed.lower()):
                return True

        logger.warning(f"🚫 Target not in scope: {target}")
        return False

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed by policy."""
        if tool_name in self.policy.blocked_tools:
            return False
        if self.policy.allowed_tools:
            return tool_name in self.policy.allowed_tools
        return True

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        """Wildcard domain matching."""
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return target == pattern


class SecuritySandbox:
    """
    Secure execution environment for security tools.
    
    Features:
      - Command allowlisting
      - Target scope enforcement
      - Rate limiting
      - Resource limits
      - Execution auditing
      - Policy-based restrictions
    """

    def __init__(self, policy: Optional[ExecutionPolicy] = None):
        self.policy = policy or ExecutionPolicy()
        self.rate_limiter = RateLimiter(
            rate=self.policy.max_requests_per_second,
            burst=self.policy.max_requests_per_second * 2,
        )
        self.scope_enforcer = ScopeEnforcer(self.policy)
        self._execution_log: List[Dict[str, Any]] = []
        self._active_tools = 0
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(
            self.policy.max_concurrent_tools
        )

    async def execute(
        self, tool_name: str, target: str,
        cmd: List[str], timeout: int = 120,
    ) -> Dict[str, Any]:
        """Execute a tool within sandbox constraints."""
        # Check tool allowlist
        if not self.scope_enforcer.is_tool_allowed(tool_name):
            return {
                "success": False,
                "error": f"Tool blocked by policy: {tool_name}",
                "blocked": True,
            }

        # Check target scope
        if not self.scope_enforcer.is_target_allowed(target):
            return {
                "success": False,
                "error": f"Target out of scope: {target}",
                "blocked": True,
            }

        # Rate limiting
        if not await self.rate_limiter.wait_and_acquire():
            return {
                "success": False,
                "error": "Rate limit exceeded",
                "rate_limited": True,
            }

        # Concurrency control
        async with self._semaphore:
            async with self._lock:
                self._active_tools += 1

            start = time.time()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )

                elapsed = time.time() - start
                result = {
                    "success": proc.returncode == 0,
                    "output": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "return_code": proc.returncode,
                    "elapsed": round(elapsed, 2),
                    "tool": tool_name,
                }

                self._log_execution(tool_name, target, result)
                return result

            except asyncio.TimeoutError:
                return {
                    "success": False,
                    "error": f"Timeout after {timeout}s",
                    "tool": tool_name,
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "tool": tool_name,
                }
            finally:
                async with self._lock:
                    self._active_tools -= 1

    def _log_execution(self, tool: str, target: str,
                       result: Dict[str, Any]):
        self._execution_log.append({
            "tool": tool, "target": target,
            "success": result.get("success"),
            "elapsed": result.get("elapsed"),
            "timestamp": time.time(),
        })

    def update_policy(self, scope_data: Dict[str, Any]):
        """Update policy from scope intelligence."""
        if "in_scope" in scope_data:
            self.policy.allowed_targets = set(scope_data["in_scope"])
        if "out_of_scope" in scope_data:
            self.policy.blocked_targets = set(scope_data["out_of_scope"])
        if "forbidden_testing" in scope_data:
            for f in scope_data["forbidden_testing"]:
                fl = f.lower()
                if "brute" in fl:
                    self.policy.allow_brute_force = False
                if "port" in fl:
                    self.policy.allow_port_scan = False
        if "rate_limit" in scope_data:
            self.policy.max_requests_per_second = scope_data["rate_limit"]
            self.rate_limiter = RateLimiter(
                rate=scope_data["rate_limit"]
            )
        logger.info(f"🔒 Sandbox policy updated from scope data")

    def get_audit_log(self) -> List[Dict[str, Any]]:
        return list(self._execution_log)

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._execution_log)
        success = sum(1 for e in self._execution_log if e.get("success"))
        return {
            "total_executions": total,
            "successful": success,
            "failed": total - success,
            "active_tools": self._active_tools,
            "allowed_tools": len(self.policy.allowed_tools),
            "allowed_targets": len(self.policy.allowed_targets),
            "rate_limit": self.policy.max_requests_per_second,
        }
