"""
╔══════════════════════════════════════════════════════════════╗
║  Coordinator Agent — The ONLY Orchestrator in the Swarm     ║
║  Routes tasks, manages priorities, monitors agents          ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from hydra.memory.bus import MemoryBus, Task, TaskPriority, TaskStatus
from hydra.config import get_config

logger = logging.getLogger("hydra.swarm.coordinator")


class CoordinatorAgent:
    """
    The Coordinator is NOT a regular agent — it is the brain of the swarm.
    
    Responsibilities:
      1. Decompose high-level scan requests into agent tasks
      2. Route tasks to the correct agent queues via MemoryBus
      3. Monitor task completion and chain dependent tasks
      4. Track global scan progress
      5. Make priority decisions based on findings
      6. Trigger the learning engine on completion
    """
    
    # Scan phases define the task pipeline
    SCAN_PHASES = [
        {
            "phase": "recon",
            "agent_type": "recon",
            "tasks": [
                {"task_type": "subdomain_enum", "priority": TaskPriority.HIGH},
                {"task_type": "http_probe", "priority": TaskPriority.HIGH},
                {"task_type": "endpoint_discovery", "priority": TaskPriority.NORMAL},
            ]
        },
        {
            "phase": "analysis",
            "agent_type": "vuln_research",
            "tasks": [
                {"task_type": "vuln_scan", "priority": TaskPriority.HIGH},
                {"task_type": "tech_detection", "priority": TaskPriority.NORMAL},
                {"task_type": "cve_lookup", "priority": TaskPriority.NORMAL},
            ],
            "depends_on": "recon",
        },
        {
            "phase": "hypothesis",
            "agent_type": "exploit_hypothesis",
            "tasks": [
                {"task_type": "attack_chain_generation", "priority": TaskPriority.NORMAL},
                {"task_type": "exploit_path_analysis", "priority": TaskPriority.NORMAL},
            ],
            "depends_on": "analysis",
        },
        {
            "phase": "validation",
            "agent_type": "validation",
            "tasks": [
                {"task_type": "false_positive_filter", "priority": TaskPriority.HIGH},
                {"task_type": "confidence_scoring", "priority": TaskPriority.HIGH},
            ],
            "depends_on": "hypothesis",
        },
        {
            "phase": "reporting",
            "agent_type": "reporting",
            "tasks": [
                {"task_type": "report_generation", "priority": TaskPriority.NORMAL},
            ],
            "depends_on": "validation",
        },
    ]
    
    def __init__(self, bus: MemoryBus, scope_engine=None, planner=None):
        self.bus = bus
        self.config = get_config()
        self._running = False
        self._active_scans: Dict[str, Dict[str, Any]] = {}
        self._phase_tracker: Dict[str, Dict[str, str]] = {}
        self._scope_engine = scope_engine
        self._planner = planner
        self._planner_plans: Dict[str, Any] = {}  # scan_id → ExecutionPlan

    def set_scope_engine(self, scope_engine):
        """Attach scope engine — all targets validated before phase launch."""
        self._scope_engine = scope_engine
        logger.info("🔒 Scope enforcement attached to Coordinator")

    def set_planner(self, planner):
        """Attach Planner Agent — Coordinator only executes Planner decisions."""
        self._planner = planner
        logger.info("🧠 Planner Agent attached to Coordinator")

    async def accept_plan(self, scan_id: str, plan):
        """Accept an ExecutionPlan from the Planner Agent."""
        self._planner_plans[scan_id] = plan
        logger.info(f"📋 Plan accepted for scan {scan_id}: {len(plan.steps)} steps")
    
    async def start_scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        """
        Initiate a full scan pipeline for a target.
        
        Returns:
            scan_id: Unique identifier for this scan.
        """
        options = options or {}
        
        # Create scan state
        scan_id = f"scan-{int(time.time())}-{hash(target) % 10000:04d}"
        scan_state = {
            "scan_id": scan_id,
            "target": target,
            "status": "running",
            "started_at": time.time(),
            "options": options,
            "phases_completed": [],
            "current_phase": "recon",
            "findings": [],
            "metrics": {
                "tasks_total": 0,
                "tasks_completed": 0,
                "tasks_failed": 0,
            },
        }
        
        await self.bus.set_state(f"scan:{scan_id}", scan_state)
        self._active_scans[scan_id] = scan_state
        self._phase_tracker[scan_id] = {}
        
        logger.info(f"🎯 Scan started: {scan_id} → {target}")
        
        # Launch the first phase
        await self._launch_phase(scan_id, target, self.SCAN_PHASES[0], options)
        
        return scan_id
    
    async def _launch_phase(
        self,
        scan_id: str,
        target: str,
        phase_config: Dict[str, Any],
        options: Dict[str, Any],
    ):
        """Launch all tasks for a given scan phase."""
        phase_name = phase_config["phase"]
        agent_type = phase_config["agent_type"]
        
        # ── MANDATORY SCOPE VALIDATION ──────────
        if self._scope_engine and self._scope_engine.is_loaded:
            scope_check = self._scope_engine.validate_target(target)
            if not scope_check.allowed:
                logger.warning(
                    f"🚫 Phase '{phase_name}' BLOCKED — target out of scope: "
                    f"{scope_check.reason}"
                )
                return
        
        logger.info(f"📋 Launching phase: {phase_name} for scan {scan_id}")
        
        # Update scan state
        scan_state = await self.bus.get_state(f"scan:{scan_id}")
        if scan_state:
            scan_state["current_phase"] = phase_name
            await self.bus.set_state(f"scan:{scan_id}", scan_state)
        
        # Gather context from previous phases
        context = await self._gather_phase_context(scan_id, phase_name)
        
        task_ids = []
        for task_def in phase_config["tasks"]:
            task = Task(
                task_type=task_def["task_type"],
                agent_type=agent_type,
                priority=task_def["priority"],
                payload={
                    "target": target,
                    "scan_id": scan_id,
                    "options": options,
                    "context": context,
                },
                metadata={
                    "scan_id": scan_id,
                    "phase": phase_name,
                    "timeout": options.get("task_timeout", 300),
                },
            )
            task_id = await self.bus.push_task(task)
            task_ids.append(task_id)
        
        # Track phase tasks
        self._phase_tracker[scan_id][phase_name] = {
            "task_ids": task_ids,
            "status": "running",
            "started_at": time.time(),
        }
        
        logger.info(
            f"📤 Phase '{phase_name}' launched with {len(task_ids)} tasks "
            f"for agent type '{agent_type}'"
        )
    
    async def _gather_phase_context(self, scan_id: str, current_phase: str) -> Dict[str, Any]:
        """Gather results from all previous phases as context for the current phase."""
        context = {}
        
        for phase_config in self.SCAN_PHASES:
            phase_name = phase_config["phase"]
            if phase_name == current_phase:
                break
            
            phase_results = await self.bus.get_list(f"phase_results:{scan_id}:{phase_name}")
            if phase_results:
                context[phase_name] = phase_results
        
        return context
    
    async def run(self):
        """
        Main coordinator loop.
        
        Monitors task completion and advances scan phases.
        """
        self._running = True
        tick_interval = self.config.swarm.coordinator_tick_interval
        
        logger.info("🎛️  Coordinator Agent started")
        
        while self._running:
            try:
                await self._tick()
                await asyncio.sleep(tick_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Coordinator tick error: {e}")
                await asyncio.sleep(1)
        
        logger.info("🎛️  Coordinator Agent stopped")
    
    async def _tick(self):
        """Single coordinator tick — check progress and advance phases."""
        for scan_id in list(self._active_scans.keys()):
            scan_state = await self.bus.get_state(f"scan:{scan_id}")
            if not scan_state or scan_state.get("status") != "running":
                continue
            
            current_phase = scan_state.get("current_phase")
            phase_info = self._phase_tracker.get(scan_id, {}).get(current_phase)
            
            if not phase_info:
                continue
            
            # Track which task results we've already collected
            collected = phase_info.get("_collected", set())
            
            # Check if all tasks in current phase are done
            all_done = True
            for task_id in phase_info["task_ids"]:
                task = await self.bus.get_task(task_id)
                if task and task.status not in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                    all_done = False
                    break
                
                # Collect results from completed tasks (only once per task)
                if (task and task.status == TaskStatus.COMPLETED
                        and task.result and task_id not in collected):
                    await self.bus.append_to_list(
                        f"phase_results:{scan_id}:{current_phase}",
                        task.result
                    )
                    collected.add(task_id)
            
            phase_info["_collected"] = collected
            
            if all_done:
                phase_info["status"] = "completed"
                scan_state["phases_completed"].append(current_phase)
                
                # Find and launch next phase
                next_phase = self._get_next_phase(current_phase)
                if next_phase:
                    # Keep the local copy consistent with what _launch_phase
                    # persists — otherwise the set_state below re-saves the OLD
                    # current_phase and (in Redis/distributed mode, where states
                    # are independent copies) the phase is re-launched forever.
                    scan_state["current_phase"] = next_phase["phase"]
                    await self._launch_phase(
                        scan_id,
                        scan_state["target"],
                        next_phase,
                        scan_state.get("options", {}),
                    )
                else:
                    # All phases complete
                    scan_state["status"] = "completed"
                    scan_state["completed_at"] = time.time()
                    logger.info(f"🏁 Scan completed: {scan_id}")
                    
                    # Trigger learning engine
                    await self.bus.publish("scan_completed", {
                        "scan_id": scan_id,
                        "target": scan_state["target"],
                    })
                
                await self.bus.set_state(f"scan:{scan_id}", scan_state)
    
    def _get_next_phase(self, current_phase: str) -> Optional[Dict[str, Any]]:
        """Get the next phase configuration after the current one."""
        found_current = False
        for phase_config in self.SCAN_PHASES:
            if found_current:
                return phase_config
            if phase_config["phase"] == current_phase:
                found_current = True
        return None
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of a scan."""
        return await self.bus.get_state(f"scan:{scan_id}")
    
    async def cancel_scan(self, scan_id: str):
        """Cancel a running scan."""
        scan_state = await self.bus.get_state(f"scan:{scan_id}")
        if scan_state:
            scan_state["status"] = "cancelled"
            scan_state["cancelled_at"] = time.time()
            await self.bus.set_state(f"scan:{scan_id}", scan_state)
            logger.info(f"🚫 Scan cancelled: {scan_id}")
    
    async def inject_priority_task(self, scan_id: str, task: Task):
        """
        Inject a high-priority task mid-scan.
        Used when findings require immediate deeper investigation.
        """
        task.priority = TaskPriority.CRITICAL
        task.metadata["scan_id"] = scan_id
        task.metadata["injected"] = True
        await self.bus.push_task(task)
        logger.info(f"⚡ Priority task injected: {task.task_type} → {task.agent_type}")
    
    async def stop(self):
        """Stop the coordinator."""
        self._running = False
