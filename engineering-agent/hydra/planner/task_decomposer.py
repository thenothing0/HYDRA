"""
╔══════════════════════════════════════════════════════════════╗
║  Task Decomposer — Goal → Subtask Decomposition Engine     ║
║  Workflow templates and intelligent task generation         ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger("hydra.planner.decomposer")


class PlanStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    REPLANNING = "replanning"


class TaskConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


@dataclass
class PlanStep:
    """A single step in an execution plan."""
    id: str
    phase: str
    task_type: str
    agent_type: str
    priority: int = 2
    confidence: str = TaskConfidence.MEDIUM
    depends_on: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = PlanStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    estimated_duration: float = 60.0
    retry_count: int = 0
    max_retries: int = 3
    condition: Optional[str] = None


@dataclass
class ExecutionPlan:
    """Complete execution plan for a target."""
    plan_id: str
    target: str
    goal: str
    steps: List[PlanStep] = field(default_factory=list)
    status: str = PlanStatus.PENDING
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    revision: int = 1
    context: Dict[str, Any] = field(default_factory=dict)
    adaptations: List[Dict[str, Any]] = field(default_factory=list)


WORKFLOW_TEMPLATES = {
    "full_assessment": {
        "description": "Complete security assessment",
        "phases": [
            {
                "phase": "scope_validation",
                "steps": [
                    {"task_type": "scope_check", "agent_type": "scope",
                     "priority": 0, "confidence": "high"},
                ],
            },
            {
                "phase": "passive_recon",
                "steps": [
                    {"task_type": "subdomain_enum", "agent_type": "recon",
                     "priority": 1, "confidence": "high"},
                    {"task_type": "dns_history", "agent_type": "recon",
                     "priority": 2, "confidence": "medium"},
                    {"task_type": "github_leak_scan", "agent_type": "recon",
                     "priority": 2, "confidence": "medium"},
                ],
                "depends_on": ["scope_validation"],
            },
            {
                "phase": "active_recon",
                "steps": [
                    {"task_type": "http_probe", "agent_type": "recon",
                     "priority": 1, "confidence": "high"},
                    {"task_type": "endpoint_discovery", "agent_type": "recon",
                     "priority": 2, "confidence": "high"},
                    {"task_type": "js_endpoint_extraction", "agent_type": "recon",
                     "priority": 2, "confidence": "medium"},
                ],
                "depends_on": ["passive_recon"],
            },
            {
                "phase": "fingerprinting",
                "steps": [
                    {"task_type": "tech_detection", "agent_type": "vuln_research",
                     "priority": 1, "confidence": "high"},
                    {"task_type": "waf_detection", "agent_type": "vuln_research",
                     "priority": 2, "confidence": "high"},
                ],
                "depends_on": ["active_recon"],
            },
            {
                "phase": "vulnerability_scanning",
                "steps": [
                    {"task_type": "vuln_scan", "agent_type": "vuln_research",
                     "priority": 1, "confidence": "high"},
                    {"task_type": "cve_lookup", "agent_type": "vuln_research",
                     "priority": 2, "confidence": "medium"},
                ],
                "depends_on": ["fingerprinting"],
            },
            {
                "phase": "exploit_analysis",
                "steps": [
                    {"task_type": "attack_chain_generation",
                     "agent_type": "exploit_hypothesis",
                     "priority": 1, "confidence": "medium"},
                    {"task_type": "exploit_path_analysis",
                     "agent_type": "exploit_hypothesis",
                     "priority": 2, "confidence": "medium"},
                ],
                "depends_on": ["vulnerability_scanning"],
            },
            {
                "phase": "validation",
                "steps": [
                    {"task_type": "false_positive_filter",
                     "agent_type": "validation",
                     "priority": 1, "confidence": "high"},
                    {"task_type": "confidence_scoring",
                     "agent_type": "validation",
                     "priority": 1, "confidence": "high"},
                ],
                "depends_on": ["exploit_analysis"],
            },
            {
                "phase": "reporting",
                "steps": [
                    {"task_type": "report_generation",
                     "agent_type": "reporting",
                     "priority": 2, "confidence": "high"},
                ],
                "depends_on": ["validation"],
            },
        ],
    },
    "quick_scan": {
        "description": "Quick vulnerability scan",
        "phases": [
            {
                "phase": "recon",
                "steps": [
                    {"task_type": "subdomain_enum", "agent_type": "recon",
                     "priority": 1},
                    {"task_type": "http_probe", "agent_type": "recon",
                     "priority": 1},
                ],
            },
            {
                "phase": "scan",
                "steps": [
                    {"task_type": "vuln_scan", "agent_type": "vuln_research",
                     "priority": 1},
                ],
                "depends_on": ["recon"],
            },
            {
                "phase": "report",
                "steps": [
                    {"task_type": "report_generation",
                     "agent_type": "reporting", "priority": 2},
                ],
                "depends_on": ["scan"],
            },
        ],
    },
    "api_assessment": {
        "description": "API-focused security assessment",
        "phases": [
            {
                "phase": "api_discovery",
                "steps": [
                    {"task_type": "endpoint_discovery", "agent_type": "recon",
                     "priority": 1},
                    {"task_type": "js_endpoint_extraction",
                     "agent_type": "recon", "priority": 1},
                ],
            },
            {
                "phase": "api_scanning",
                "steps": [
                    {"task_type": "vuln_scan", "agent_type": "vuln_research",
                     "priority": 1,
                     "parameters": {"tags": "api,graphql,rest"}},
                ],
                "depends_on": ["api_discovery"],
            },
            {
                "phase": "analysis",
                "steps": [
                    {"task_type": "attack_chain_generation",
                     "agent_type": "exploit_hypothesis", "priority": 1},
                    {"task_type": "report_generation",
                     "agent_type": "reporting", "priority": 2},
                ],
                "depends_on": ["api_scanning"],
            },
        ],
    },
}


class TaskDecomposer:
    """Breaks high-level goals into executable subtasks."""

    GOAL_PATTERNS = [
        (["full", "complete", "comprehensive", "assess"], "full_assessment"),
        (["quick", "fast", "rapid", "scan"], "quick_scan"),
        (["api", "rest", "graphql", "endpoint"], "api_assessment"),
    ]

    def decompose(
        self, goal: str, target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionPlan:
        """Decompose a high-level goal into an execution plan."""
        template_name = self._match_template(goal)
        template = WORKFLOW_TEMPLATES.get(
            template_name, WORKFLOW_TEMPLATES["full_assessment"]
        )

        plan_id = f"plan-{int(time.time())}-{hash(target) % 10000:04d}"
        plan = ExecutionPlan(
            plan_id=plan_id, target=target, goal=goal,
            context=context or {},
        )

        step_counter = 0
        phase_step_map: Dict[str, List[str]] = {}

        for phase_def in template["phases"]:
            phase_name = phase_def["phase"]
            phase_step_ids = []

            depends_on_steps = []
            for dep_phase in phase_def.get("depends_on", []):
                depends_on_steps.extend(
                    phase_step_map.get(dep_phase, [])
                )

            for step_def in phase_def["steps"]:
                step_id = f"{plan_id}:step-{step_counter:03d}"
                step_counter += 1
                step = PlanStep(
                    id=step_id,
                    phase=phase_name,
                    task_type=step_def["task_type"],
                    agent_type=step_def["agent_type"],
                    priority=step_def.get("priority", 2),
                    confidence=step_def.get("confidence",
                                            TaskConfidence.MEDIUM),
                    depends_on=list(depends_on_steps),
                    parameters=step_def.get("parameters", {}),
                )
                plan.steps.append(step)
                phase_step_ids.append(step_id)

            phase_step_map[phase_name] = phase_step_ids

        logger.info(
            f"Decomposed '{goal[:50]}' → {len(plan.steps)} steps "
            f"(template: {template_name})"
        )
        return plan

    def _match_template(self, goal: str) -> str:
        goal_lower = goal.lower()
        for patterns, template_name in self.GOAL_PATTERNS:
            if any(p in goal_lower for p in patterns):
                return template_name
        return "full_assessment"
