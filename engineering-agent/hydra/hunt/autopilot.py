"""
╔══════════════════════════════════════════════════════════════╗
║  Autopilot — Full Autonomous Bug Bounty Mode                ║
║  Recon → Hunt → Chain → Validate → Report (zero interaction)║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.hunt.autopilot")


class AutopilotMode(str, Enum):
    NORMAL = "normal"       # Confirms before destructive steps
    AGGRESSIVE = "aggressive"  # No confirmation, max coverage
    STEALTH = "stealth"     # Low rate, minimal footprint
    PARANOID = "paranoid"   # Confirms every single action


@dataclass
class AutopilotConfig:
    mode: AutopilotMode = AutopilotMode.NORMAL
    max_duration_minutes: int = 60
    max_findings: int = 100
    recon_depth: str = "full"       # quick | full | deep
    hunt_classes: List[str] = field(default_factory=lambda: ["auto"])
    enable_chain_building: bool = True
    enable_reporting: bool = True
    rate_limit_rps: int = 50
    concurrent_agents: int = 5


@dataclass
class AutopilotResult:
    target: str
    mode: str
    duration_seconds: float = 0
    phases_completed: List[str] = field(default_factory=list)
    total_findings: int = 0
    chains_built: int = 0
    report_path: str = ""
    success: bool = False
    error: str = ""


class AutopilotEngine:
    """
    Fully autonomous bug bounty pipeline.
    
    Executes the complete lifecycle:
    1. Scope validation
    2. Reconnaissance (subdomain, tech, ports, URLs)
    3. Vulnerability hunting (all vuln classes)
    4. Exploit chain building
    5. Finding validation
    6. Report generation
    """

    def __init__(self, hunt_engine=None, chain_builder=None,
                 coordinator=None, planner=None, scope_engine=None,
                 artifact_store=None, mcp_client=None):
        self.hunt = hunt_engine
        self.chains = chain_builder
        self.coordinator = coordinator
        self.planner = planner
        self.scope = scope_engine
        self.artifacts = artifact_store
        self.mcp = mcp_client
        self._running = False

    async def run(self, target: str,
                  config: Optional[AutopilotConfig] = None) -> AutopilotResult:
        """Execute full autonomous pipeline."""
        config = config or AutopilotConfig()
        result = AutopilotResult(target=target, mode=config.mode.value)
        start = time.time()
        self._running = True

        logger.info(f"🤖 Autopilot engaged: {target} | mode={config.mode.value}")

        try:
            # Phase 1: Scope validation
            if self.scope and self.scope.is_loaded:
                check = self.scope.validate_target(target)
                if not check.allowed:
                    result.error = f"Target out of scope: {check.reason}"
                    logger.error(f"🚫 {result.error}")
                    return result
            result.phases_completed.append("scope_validation")

            # Phase 2: Reconnaissance
            logger.info("🔍 Phase 2: Reconnaissance...")
            recon_data = await self._run_recon(target, config)
            result.phases_completed.append("reconnaissance")

            # Phase 3: Vulnerability hunting
            logger.info("🎯 Phase 3: Vulnerability Hunting...")
            if self.hunt:
                hunt_session = await self.hunt.hunt(
                    target=target,
                    vuln_class="auto" if "auto" in config.hunt_classes else config.hunt_classes[0],
                    mode=config.mode.value,
                    max_cycles=15,
                    timeout_minutes=config.max_duration_minutes // 2,
                )
                result.total_findings = hunt_session.total_findings
            result.phases_completed.append("hunting")

            # Phase 4: Exploit chain building
            if config.enable_chain_building and self.chains:
                logger.info("⛓️ Phase 4: Building Exploit Chains...")
                all_findings = []
                if self.hunt and hasattr(self.hunt, '_active_sessions'):
                    for session in self.hunt._active_sessions.values():
                        for cycle in session.cycles:
                            all_findings.extend(cycle.findings)
                if all_findings:
                    chains = self.chains.build_chains(all_findings, target)
                    result.chains_built = len(chains)
                result.phases_completed.append("chain_building")

            # Phase 5: Validation
            logger.info("✅ Phase 5: Validating Findings...")
            if self.coordinator:
                await self._validate_findings(target)
            result.phases_completed.append("validation")

            # Phase 6: Reporting
            if config.enable_reporting:
                logger.info("📄 Phase 6: Generating Report...")
                report_path = await self._generate_report(target, result)
                result.report_path = report_path
                result.phases_completed.append("reporting")

            result.success = True

        except asyncio.CancelledError:
            logger.info("Autopilot cancelled")
            result.error = "cancelled"
        except Exception as e:
            logger.error(f"Autopilot error: {e}", exc_info=True)
            result.error = str(e)
        finally:
            self._running = False
            result.duration_seconds = round(time.time() - start, 1)

        logger.info(
            f"🏁 Autopilot complete: {result.total_findings} findings, "
            f"{result.chains_built} chains, {result.duration_seconds}s"
        )
        return result

    async def _run_recon(self, target: str, config: AutopilotConfig) -> Dict:
        """Run reconnaissance phase via MCP tools."""
        recon_data: Dict[str, Any] = {"subdomains": [], "endpoints": [], "tech": []}
        if not self.mcp:
            return recon_data

        # Subdomain enumeration
        sub_result = await self.mcp.execute_tool(
            "subdomain_enum", {"target": target, "timeout": 120}
        )
        if sub_result.get("success") and sub_result.get("output"):
            recon_data["subdomains"] = [
                l.strip() for l in sub_result["output"].strip().split("\n") if l.strip()
            ]

        # HTTP probing
        probe_result = await self.mcp.execute_tool(
            "http_probe", {"target": target, "timeout": 60}
        )
        if probe_result.get("success") and probe_result.get("output"):
            recon_data["endpoints"] = [
                l.strip() for l in probe_result["output"].strip().split("\n") if l.strip()
            ]

        # Tech detection
        tech_result = await self.mcp.execute_tool(
            "tech_detect", {"target": target, "timeout": 30}
        )
        if tech_result.get("success") and tech_result.get("output"):
            recon_data["tech"] = tech_result["output"].strip().split("\n")

        if self.artifacts:
            self.artifacts.save_parsed_output(target, "recon", "autopilot_recon", recon_data)

        logger.info(
            f"📊 Recon: {len(recon_data['subdomains'])} subdomains, "
            f"{len(recon_data['endpoints'])} endpoints"
        )
        return recon_data

    async def _validate_findings(self, target: str) -> None:
        """Trigger validation phase via coordinator."""
        pass  # Coordinator handles this through its phase system

    async def _generate_report(self, target: str, result: AutopilotResult) -> str:
        """Generate final report and save as artifact."""
        report = {
            "target": target, "mode": result.mode,
            "findings": result.total_findings,
            "chains": result.chains_built,
            "phases": result.phases_completed,
            "duration_s": result.duration_seconds,
        }
        if self.artifacts:
            path = self.artifacts.save_report(target, "autopilot_report", report)
            return str(path) if path else ""
        return ""

    async def stop(self):
        """Gracefully stop autopilot."""
        self._running = False
        logger.info("🛑 Autopilot stop requested")
