"""
╔══════════════════════════════════════════════════════════════╗
║  Autonomous Hunt Engine — Self-Directed Vulnerability Hunting║
║  Adaptive loops, vuln-class strategies, success tracking     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from hydra.hunt.strategies import (
    STRATEGY_REGISTRY, HuntStrategy, get_strategy, get_priority_ordered,
)
from hydra.hunt.safety import (
    EvidenceLevel, is_exploitation_payload, benign_probes_for,
    benign_probe_variants, assess_probe,
)
from hydra.hunt.prober import SafeProber

logger = logging.getLogger("hydra.hunt")


class HuntStatus(str, Enum):
    IDLE = "idle"
    HUNTING = "hunting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnClass(str, Enum):
    SSRF = "ssrf"
    IDOR = "idor"
    XSS = "xss"
    SQLI = "sqli"
    OAUTH = "oauth"
    AUTHZ = "authz"
    RCE = "rce"
    LFI = "lfi"
    SSTI = "ssti"
    CORS = "cors"
    OPEN_REDIRECT = "open_redirect"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    NEXTJS = "nextjs"
    AUTO = "auto"


@dataclass
class HuntCycle:
    cycle_id: int
    vuln_class: str
    targets_tested: int = 0
    findings: List[Dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0
    duration_s: float = 0
    success: bool = False


@dataclass
class HuntSession:
    target: str
    session_id: str = ""
    status: HuntStatus = HuntStatus.IDLE
    mode: str = "normal"  # normal | aggressive | stealth
    cycles: List[HuntCycle] = field(default_factory=list)
    total_findings: int = 0
    vuln_classes_tested: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0


# NOTE: vuln-class playbooks now live in a single source of truth,
# ``hydra/hunt/strategies.py`` (``STRATEGY_REGISTRY`` / ``HuntStrategy``).
# The engine below consumes them via ``get_strategy`` / ``get_priority_ordered``.
# The old inline ``HUNT_STRATEGIES`` dict (a divergent second copy) was removed.


class HuntEngine:
    """
    Autonomous Hunt Engine.
    
    Runs self-directed vulnerability hunting loops with
    adaptive strategy selection, success tracking, and
    automatic escalation when high-severity findings emerge.
    """

    def __init__(self, coordinator=None, planner=None, mcp_client=None,
                 scope_engine=None, artifact_store=None, semantic_memory=None,
                 active_probing=False, prober=None, rate_limiter=None):
        self.coordinator = coordinator
        self.planner = planner
        self.mcp = mcp_client
        self.scope = scope_engine
        self.artifacts = artifact_store
        self.memory = semantic_memory
        # Active probing is OFF by default: nuclei-only (Phase 1) unless the
        # operator opts in with --hunt-active. Even when ON it stays benign,
        # scope-gated, and rate-limited (see hydra/hunt/prober.py + safety.py).
        self.active_probing = active_probing
        self.rate_limiter = rate_limiter
        self.prober = prober
        self._active_sessions: Dict[str, HuntSession] = {}
        self._hunt_history: List[Dict] = []

    def _get_prober(self) -> SafeProber:
        """Lazily build the single guarded HTTP probe primitive."""
        if self.prober is None:
            self.prober = SafeProber(scope_engine=self.scope,
                                     rate_limiter=self.rate_limiter)
        return self.prober

    async def hunt(self, target: str, vuln_class: str = "auto",
                   mode: str = "normal", max_cycles: int = 10,
                   timeout_minutes: int = 30) -> HuntSession:
        """Run an autonomous hunt session."""
        session = HuntSession(
            target=target,
            session_id=f"hunt-{int(time.time())}",
            mode=mode,
            status=HuntStatus.HUNTING,
        )
        self._active_sessions[session.session_id] = session
        logger.info(f"🎯 Hunt started: {target} | class={vuln_class} | mode={mode}")

        # Scope check
        if self.scope and self.scope.is_loaded:
            check = self.scope.validate_target(target)
            if not check.allowed:
                logger.error(f"🚫 Hunt blocked — target out of scope: {check.reason}")
                session.status = HuntStatus.FAILED
                return session

        # Determine which vuln classes to hunt
        if vuln_class == "auto":
            classes = await self._select_priority_classes(target)
        else:
            classes = [vuln_class]

        deadline = time.time() + (timeout_minutes * 60)
        cycle_num = 0

        for vc in classes:
            if cycle_num >= max_cycles or time.time() > deadline:
                break

            strategy = get_strategy(vc)
            if not strategy:
                continue

            cycle = HuntCycle(cycle_id=cycle_num, vuln_class=vc)
            logger.info(f"🔄 Hunt cycle {cycle_num}: {strategy.name}")

            try:
                findings = await self._execute_hunt_cycle(target, vc, strategy, mode)
                cycle.findings = findings
                cycle.targets_tested = max(1, len(findings))
                cycle.success = len(findings) > 0
                cycle.ended_at = time.time()
                cycle.duration_s = cycle.ended_at - cycle.started_at
            except Exception as e:
                logger.error(f"Hunt cycle {cycle_num} failed: {e}")
                cycle.ended_at = time.time()

            session.cycles.append(cycle)
            session.total_findings += len(cycle.findings)
            session.vuln_classes_tested.append(vc)
            cycle_num += 1

            # Adaptive: if high-severity found, escalate
            if any(f.get("severity", "").lower() in ("critical", "high") for f in cycle.findings):
                logger.info(f"🔥 High-severity finding! Escalating hunt...")
                if self.planner:
                    await self.planner.replan(
                        plan_id=session.session_id,
                        findings=cycle.findings,
                        reason="high_severity_finding",
                    )

            # Save artifacts
            if self.artifacts:
                self.artifacts.save_parsed_output(
                    target, "scans", f"hunt_cycle_{cycle_num}",
                    {"cycle": cycle_num, "class": vc, "findings": cycle.findings}
                )

        # Finalize session
        session.status = HuntStatus.COMPLETED
        session.ended_at = time.time()
        total_cycles = len(session.cycles)
        successful = sum(1 for c in session.cycles if c.success)
        session.success_rate = round(successful / max(total_cycles, 1) * 100, 1)

        logger.info(
            f"✅ Hunt complete: {session.total_findings} findings, "
            f"{session.success_rate}% success rate ({successful}/{total_cycles} cycles)"
        )

        # Store in memory for future hunts
        if self.memory:
            try:
                await self.memory.store(
                    content=f"Hunt session on {target}: {session.total_findings} findings, "
                            f"classes: {session.vuln_classes_tested}, "
                            f"success_rate: {session.success_rate}%",
                    metadata={"type": "hunt_session", "target": target,
                              "findings": session.total_findings},
                )
            except Exception:
                pass

        self._hunt_history.append({
            "session_id": session.session_id, "target": target,
            "findings": session.total_findings, "success_rate": session.success_rate,
            "classes": session.vuln_classes_tested, "timestamp": time.time(),
        })

        return session

    async def _select_priority_classes(self, target: str) -> List[str]:
        """Priority-ordered vuln classes to hunt (highest priority first)."""
        # Check memory for what worked on similar targets (advisory only).
        if self.memory:
            try:
                similar = await self.memory.search(
                    query=f"successful hunt strategies for {target}",
                    n_results=5,
                )
                if similar:
                    logger.info(f"📚 Found {len(similar)} similar hunt sessions in memory")
            except Exception:
                pass

        # Single source of truth: strategies.py, ordered by its own priority.
        return [s.vuln_class for s in get_priority_ordered()]

    async def _execute_hunt_cycle(self, target: str, vuln_class: str,
                                   strategy: HuntStrategy, mode: str) -> List[Dict]:
        """One hunt cycle for a vuln class.

        Phase 1 (always): nuclei with the class's templates — the safe workhorse.
        Phase 2/3 (opt-in, ``--hunt-active`` only): benign, scope-gated,
        rate-limited detection probes. We NEVER inject the exploitation payloads
        carried in ``strategy.payloads``; only curated benign probes
        (safety.benign_probes_for) and GET path-existence checks are sent.
        """
        findings: List[Dict] = []
        if not self.mcp:
            logger.warning("No MCP client — hunt cycle skipped")
            return findings

        # ── Phase 1: nuclei, class-tagged (detection-grade, no exploitation) ──
        if "nuclei" in strategy.tools and strategy.nuclei_tags:
            tags = ",".join(strategy.nuclei_tags)
            severity = ("low,medium,high,critical" if mode == "aggressive"
                        else strategy.severity_range)
            result = await self.mcp.execute_tool(
                "nuclei_scan",
                {"target": target, "severity": severity, "tags": tags},
            )
            if result.get("success") and result.get("output"):
                parsed = self._parse_nuclei_output(result["output"])
                for f in parsed:
                    f["hunt_class"] = vuln_class
                    f["hunt_source"] = "nuclei"
                    f.setdefault("evidence_level", EvidenceLevel.OBSERVED)
                findings.extend(parsed)

        # ── Phase 2/3: active probing — OFF unless the operator opted in ──
        if self.active_probing:
            prober = self._get_prober()
            budget = [strategy.max_requests]   # shared mutable request ceiling
            findings.extend(
                await self._probe_paths(target, vuln_class, strategy, prober, budget))
            findings.extend(
                await self._probe_params(target, vuln_class, strategy, prober, budget))

        return findings

    @staticmethod
    def _base_url(target: str) -> str:
        t = (target or "").strip()
        return t if "://" in t else "https://" + t

    async def _probe_paths(self, target, vuln_class, strategy, prober,
                           budget) -> List[Dict]:
        """Phase 2 — benign GET existence checks over the class's known paths."""
        findings: List[Dict] = []
        base = self._base_url(target).rstrip("/")
        for path in (strategy.paths_to_check or [])[:20]:
            if budget[0] <= 0:
                break
            budget[0] -= 1
            resp = await prober.get(base + path)
            if not resp.ok:
                continue
            if resp.status == 200:
                matched = next((p for p in strategy.detection_patterns
                                if p in resp.body), "")
                findings.append({
                    "name": f"Exposed path: {path}",
                    "type": vuln_class, "matched_at": base + path,
                    "severity": "medium" if matched else "low",
                    "hunt_class": vuln_class, "hunt_source": "prober",
                    "evidence_level": (EvidenceLevel.INFERRED if matched
                                       else EvidenceLevel.OBSERVED),
                    "evidence": (f"HTTP 200; matched '{matched}'" if matched
                                 else "HTTP 200"),
                    "confidence_score": 0.7 if matched else 0.5,
                })
            elif resp.status in (401, 403):
                findings.append({
                    "name": f"Protected path exists: {path} (HTTP {resp.status})",
                    "type": vuln_class, "matched_at": base + path,
                    "severity": "info", "hunt_class": vuln_class,
                    "hunt_source": "prober",
                    "evidence_level": EvidenceLevel.OBSERVED,
                    "evidence": f"HTTP {resp.status}", "confidence_score": 0.3,
                })
        return findings

    async def _probe_params(self, target, vuln_class, strategy, prober,
                            budget) -> List[Dict]:
        """Phase 3 — benign, detection-only parameter probes (never exploit).

        Tries each class's benign probe and its harmless WAF-bypass encodings
        (``benign_probe_variants``) so a filter that blocks the literal probe
        doesn't cause a false negative. What lands is still benign either way.
        """
        findings: List[Dict] = []
        probes = benign_probe_variants(vuln_class)
        if not probes or not strategy.parameter_targets:
            return findings
        base = self._base_url(target)
        for param in strategy.parameter_targets[:8]:
            for probe in probes:
                if budget[0] <= 0:
                    return findings
                # Defense-in-depth: never transmit an exploitation-grade value.
                if is_exploitation_payload(probe.payload):
                    continue
                control_body = ""
                if probe.control:
                    budget[0] -= 1
                    cresp = await prober.probe_param(base, param, probe.control)
                    control_body = cresp.body if cresp.ok else ""
                budget[0] -= 1
                resp = await prober.probe_param(base, param, probe.payload)
                if not resp.ok:
                    continue
                if assess_probe(probe, body=resp.body, location=resp.location,
                                control_body=control_body):
                    findings.append({
                        "name": f"Possible {vuln_class.upper()} via '{param}' ({probe.note})",
                        "type": vuln_class, "matched_at": resp.url,
                        "severity": self._probe_severity(vuln_class, probe),
                        "hunt_class": vuln_class, "hunt_source": "prober",
                        "evidence_level": probe.evidence,
                        "evidence": f"benign probe {probe.payload!r} → {probe.note}",
                        "confidence_score": 0.5,
                        "note": "Detection-grade only — benign probe, not exploited.",
                    })
                    break   # one confirmation per parameter is enough
        return findings

    @staticmethod
    def _probe_severity(vuln_class: str, probe) -> str:
        # Reflection-only leads stay LOW (reflection ≠ execution). Strong
        # inferred/observed signals get a class-appropriate, still-conservative
        # severity — never "critical" without exploitation (which we never do).
        if probe.evidence == EvidenceLevel.UNVERIFIED:
            return "low"
        return {"sqli": "high", "ssti": "high",
                "open_redirect": "medium"}.get(vuln_class, "medium")

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse nuclei JSONL output into findings."""
        import json
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "name": data.get("info", {}).get("name", data.get("template-id", "")),
                    "type": data.get("type", "nuclei"),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "matched_at": data.get("matched-at", data.get("host", "")),
                    "template_id": data.get("template-id", ""),
                    "evidence": data.get("extracted-results", data.get("matcher-name", "")),
                    "confidence_score": 0.85,
                    "reproduction_steps": f"nuclei -u {data.get('host', '')} -t {data.get('template-id', '')}",
                })
            except (json.JSONDecodeError, KeyError):
                if "[" in line and "]" in line:
                    findings.append({
                        "name": line, "type": "nuclei_raw",
                        "severity": "info", "matched_at": line,
                        "confidence_score": 0.5,
                    })
        return findings

    def get_session(self, session_id: str) -> Optional[HuntSession]:
        return self._active_sessions.get(session_id)

    def get_hunt_history(self) -> List[Dict]:
        return list(self._hunt_history)

    def get_strategy(self, vuln_class: str) -> Optional[HuntStrategy]:
        return get_strategy(vuln_class)

    def list_strategies(self) -> Dict[str, str]:
        return {s.vuln_class: s.name for s in STRATEGY_REGISTRY.values()}
