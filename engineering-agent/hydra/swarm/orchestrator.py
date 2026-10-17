"""
╔══════════════════════════════════════════════════════════════╗
║  Swarm Orchestrator — Single-Process Swarm Runner           ║
║  Wires Coordinator + pipeline agents in one event loop      ║
╚══════════════════════════════════════════════════════════════╝

The distributed deployment (Redis + separate coordinator/worker nodes) is one
way to run the swarm; this is the other. ``SwarmOrchestrator`` brings up the
Coordinator and the five pipeline agents inside a single process, sharing one
in-memory ``MemoryBus`` — no Redis, no containers — and drives a scan end to
end. It is what ``main.py``'s ``_wf_swarm`` calls.

Doctrine notes:
  - Scope is fail-closed. The orchestrator attaches whatever ``scope_engine``
    it is given to the Coordinator (``set_scope_engine``); the Coordinator then
    validates every target before launching a phase. ``_wf_swarm`` also runs
    HYDRA's standard pre-flight scope gate before ever constructing this.
  - Nothing here sends traffic. Agents call the MCP tool layer; the never-send
    guardrails (``SafeProber``/``is_exploitation_payload``) live below that and
    are untouched by the swarm path.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from hydra.memory.bus import MemoryBus
from hydra.swarm.coordinator import CoordinatorAgent
from hydra.swarm.registry import build_agents, PIPELINE_AGENT_TYPES

logger = logging.getLogger("hydra.swarm.orchestrator")

# A scan can never be considered "done" while any of these are still true.
_TERMINAL_STATES = {"completed", "cancelled", "failed"}


class SwarmOrchestrator:
    """
    Run a full swarm scan in a single process.

    Usage:
        orch = SwarmOrchestrator(mcp_client=mcp, scope_engine=scope)
        result = await orch.run_scan("https://example.com", options={...})
    """

    def __init__(
        self,
        bus: Optional[MemoryBus] = None,
        mcp_client=None,
        ai_router=None,
        scope_engine=None,
        agent_types: Optional[List[str]] = None,
        poll_interval: float = 0.5,
        timeout: Optional[float] = None,
        **extra_deps,
    ):
        self.bus = bus or MemoryBus()
        self._owns_bus = bus is None
        self.mcp = mcp_client
        self.ai = ai_router
        self.scope = scope_engine
        self.agent_types = list(agent_types or PIPELINE_AGENT_TYPES)
        self.poll_interval = poll_interval
        self.timeout = timeout
        # Dependency bag handed to build_agent — each agent takes the subset it
        # declares (see registry.build_agent).
        self._deps = {"mcp_client": mcp_client, "ai_router": ai_router, **extra_deps}

        self.coordinator: Optional[CoordinatorAgent] = None
        self._agents: List = []
        self._loop_tasks: List[asyncio.Task] = []

    async def run_scan(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Bring up the swarm, run one scan to completion, tear it down, and return
        the collected results (scan state + per-phase results + findings).
        """
        options = options or {}
        await self.bus.connect()

        # Coordinator is the ONLY orchestrator; give it the scope engine so it
        # fail-closes at every phase launch.
        self.coordinator = CoordinatorAgent(self.bus, scope_engine=self.scope)
        if self.scope is not None:
            self.coordinator.set_scope_engine(self.scope)

        self._agents = build_agents(self.agent_types, self.bus, **self._deps)

        logger.info(
            f"🐝 Swarm starting: {len(self._agents)} agents "
            f"({', '.join(self.agent_types)})"
        )

        # Start every agent's pull loop plus the coordinator loop.
        self._loop_tasks = [asyncio.create_task(a.run()) for a in self._agents]
        self._loop_tasks.append(asyncio.create_task(self.coordinator.run()))

        try:
            scan_id = await self.coordinator.start_scan(target, options)
            await self._await_completion(scan_id)
            result = await self._collect_results(scan_id)
        finally:
            await self.shutdown()

        return result

    async def _await_completion(self, scan_id: str):
        """Poll scan state until it reaches a terminal status or times out."""
        deadline = (time.time() + self.timeout) if self.timeout else None

        while True:
            state = await self.coordinator.get_scan_status(scan_id)
            status = (state or {}).get("status")
            if status in _TERMINAL_STATES:
                return

            if deadline is not None and time.time() > deadline:
                logger.warning(
                    f"⏰ Swarm scan {scan_id} timed out after {self.timeout}s "
                    f"(last status: {status}) — cancelling"
                )
                await self.coordinator.cancel_scan(scan_id)
                return

            await asyncio.sleep(self.poll_interval)

    async def _collect_results(self, scan_id: str) -> Dict[str, Any]:
        """Gather the final scan state and every phase's results off the bus."""
        state = await self.coordinator.get_scan_status(scan_id)

        phase_results: Dict[str, Any] = {}
        for phase_config in CoordinatorAgent.SCAN_PHASES:
            phase = phase_config["phase"]
            phase_results[phase] = await self.bus.get_list(
                f"phase_results:{scan_id}:{phase}"
            )

        # Surface findings from wherever an agent emitted them, so callers get a
        # flat list regardless of which phase produced each one.
        findings: List[Dict[str, Any]] = []
        for results in phase_results.values():
            for r in results:
                if isinstance(r, dict):
                    for f in r.get("findings", []) or []:
                        findings.append(f)
                    for f in r.get("scored_findings", []) or []:
                        findings.append(f)

        return {
            "scan_id": scan_id,
            "target": (state or {}).get("target"),
            "status": (state or {}).get("status", "unknown"),
            "phases_completed": (state or {}).get("phases_completed", []),
            "state": state,
            "phase_results": phase_results,
            "findings": findings,
            "agent_metrics": [a.get_metrics() for a in self._agents],
        }

    async def shutdown(self):
        """Stop all loops, cancel their tasks, and release the bus if we own it."""
        for agent in self._agents:
            await agent.stop()
        if self.coordinator is not None:
            await self.coordinator.stop()

        for t in self._loop_tasks:
            t.cancel()
        if self._loop_tasks:
            await asyncio.gather(*self._loop_tasks, return_exceptions=True)
        self._loop_tasks = []

        if self._owns_bus:
            await self.bus.disconnect()

        logger.info("🐝 Swarm stopped")
