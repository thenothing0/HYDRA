"""SwarmWorkflows: internal methods over the security engine state."""

import logging

logger = logging.getLogger("hydra.security")


class SwarmWorkflows:
    async def _wf_swarm(self):
        """Multi-agent swarm scan in a single process.

        Brings up the Coordinator + the five pipeline agents over one in-memory
        bus (no Redis) and drives a full
        recon → analysis → hypothesis → validation → reporting pipeline.

        Scope: the Coordinator scope-gates every phase (fail-closed) — ``run()``
        has already gated the primary target, and the loaded scope engine is
        handed through so each phase re-validates. Nothing here sends traffic;
        agents call the MCP tool layer, below which the never-send guardrails
        (SafeProber / is_exploitation_payload) live untouched.
        """
        from hydra.swarm import SwarmOrchestrator

        logger.info("[bold]── Multi-Agent Swarm ──[/bold]")
        # Only hand over a *loaded* engine; an unloaded one would make the
        # Coordinator's per-phase gate a no-op. When no scope is loaded, run()
        # has already required --allow-no-scope to reach here.
        scope = self._scope if (self._scope and self._scope.is_loaded) else None

        orch = SwarmOrchestrator(
            mcp_client=self.mcp,
            scope_engine=scope,
            timeout=self.timeout or None,
        )
        result = await orch.run_scan(self.target, {"task_timeout": self.timeout})

        # Surface swarm output through the standard engine channels so the shared
        # summary/report path in run() picks it up unchanged.
        self.recon_data["swarm_phases_completed"] = result.get("phases_completed", [])
        self.findings = result.get("findings", []) or []
        self._save_json("scans/swarm_result.json", result)
        logger.info(
            f"  Swarm status=[cyan]{result.get('status')}[/] "
            f"findings=[red]{len(self.findings)}[/]"
        )
