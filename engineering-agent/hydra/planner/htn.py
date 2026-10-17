"""
╔══════════════════════════════════════════════════════════════╗
║  HTN Planner — Hierarchical Task Network Planning           ║
║  Decomposes high-level goals into executable task chains    ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.planner.htn")


@dataclass
class HTNTask:
    """A task in the Hierarchical Task Network."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    task_type: str = "primitive"  # primitive | compound | method
    agent_type: str = ""
    subtasks: List["HTNTask"] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    effects: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    estimated_duration_s: int = 30
    decomposed: bool = False

    def is_primitive(self) -> bool:
        return self.task_type == "primitive" and not self.subtasks

    def to_dict(self) -> Dict:
        return {
            "id": self.task_id, "name": self.name, "type": self.task_type,
            "agent": self.agent_type, "priority": self.priority,
            "preconditions": self.preconditions, "effects": self.effects,
            "subtasks": [s.to_dict() for s in self.subtasks],
        }


@dataclass
class HTNMethod:
    """Decomposition method: maps compound task → subtask sequence."""
    name: str
    compound_task: str    # name of compound task this decomposes
    preconditions: List[str] = field(default_factory=list)
    subtask_names: List[str] = field(default_factory=list)
    priority: int = 1     # lower = preferred method


# ═══════════════════════════════════════════
#  Pre-defined decomposition methods
# ═══════════════════════════════════════════

METHODS: List[HTNMethod] = [
    HTNMethod(
        name="full_assessment_method",
        compound_task="full_assessment",
        subtask_names=["recon", "vuln_scan", "hunt", "chain_build", "validate", "report"],
    ),
    HTNMethod(
        name="recon_method",
        compound_task="recon",
        subtask_names=["subdomain_enum", "http_probe", "tech_detect", "port_scan", "url_discovery"],
    ),
    HTNMethod(
        name="vuln_scan_method",
        compound_task="vuln_scan",
        subtask_names=["nuclei_scan", "custom_checks"],
    ),
    HTNMethod(
        name="hunt_method",
        compound_task="hunt",
        subtask_names=["hunt_ssrf", "hunt_idor", "hunt_authz", "hunt_xss", "hunt_sqli"],
    ),
    HTNMethod(
        name="chain_build_method",
        compound_task="chain_build",
        subtask_names=["collect_findings", "build_chains", "score_chains", "generate_pocs"],
    ),
    HTNMethod(
        name="validate_method",
        compound_task="validate",
        subtask_names=["evidence_check", "replay_verify", "consensus_vote"],
    ),
    HTNMethod(
        name="report_method",
        compound_task="report",
        subtask_names=["generate_findings", "build_report", "export_report"],
    ),
    # Quick recon decomposition
    HTNMethod(
        name="quick_recon_method",
        compound_task="quick_recon",
        subtask_names=["subdomain_enum", "http_probe", "nuclei_scan"],
        priority=0,
    ),
    # API assessment
    HTNMethod(
        name="api_assessment_method",
        compound_task="api_assessment",
        subtask_names=["api_discovery", "auth_testing", "api_fuzz", "validate", "report"],
    ),
    # Web3 audit
    HTNMethod(
        name="web3_audit_method",
        compound_task="web3_audit",
        subtask_names=["contract_analysis", "defi_patterns", "token_check", "report"],
    ),
]

# Primitive task definitions (agent + tool mapping)
PRIMITIVES: Dict[str, Dict[str, Any]] = {
    "subdomain_enum": {"agent": "recon", "tool": "subfinder", "timeout": 120},
    "http_probe": {"agent": "recon", "tool": "httpx", "timeout": 60},
    "tech_detect": {"agent": "recon", "tool": "whatweb", "timeout": 30},
    "port_scan": {"agent": "recon", "tool": "nmap", "timeout": 120},
    "url_discovery": {"agent": "recon", "tool": "katana", "timeout": 120},
    "nuclei_scan": {"agent": "vuln_research", "tool": "nuclei", "timeout": 300},
    "custom_checks": {"agent": "vuln_research", "tool": None, "timeout": 60},
    "hunt_ssrf": {"agent": "hunt", "vuln_class": "ssrf", "timeout": 120},
    "hunt_idor": {"agent": "hunt", "vuln_class": "idor", "timeout": 120},
    "hunt_authz": {"agent": "hunt", "vuln_class": "authz", "timeout": 120},
    "hunt_xss": {"agent": "hunt", "vuln_class": "xss", "timeout": 120},
    "hunt_sqli": {"agent": "hunt", "vuln_class": "sqli", "timeout": 120},
    "collect_findings": {"agent": "coordinator", "timeout": 10},
    "build_chains": {"agent": "exploit_hypothesis", "timeout": 60},
    "score_chains": {"agent": "exploit_hypothesis", "timeout": 30},
    "generate_pocs": {"agent": "exploit_hypothesis", "timeout": 60},
    "evidence_check": {"agent": "validation", "timeout": 60},
    "replay_verify": {"agent": "validation", "timeout": 120},
    "consensus_vote": {"agent": "validation", "timeout": 30},
    "generate_findings": {"agent": "reporting", "timeout": 30},
    "build_report": {"agent": "reporting", "timeout": 60},
    "export_report": {"agent": "reporting", "timeout": 30},
    "api_discovery": {"agent": "api_specialist", "timeout": 60},
    "auth_testing": {"agent": "api_specialist", "timeout": 120},
    "api_fuzz": {"agent": "vuln_research", "tool": "ffuf", "timeout": 120},
    "contract_analysis": {"agent": "web3_specialist", "timeout": 120},
    "defi_patterns": {"agent": "web3_specialist", "timeout": 60},
    "token_check": {"agent": "web3_specialist", "timeout": 60},
}


class HTNPlanner:
    """
    Hierarchical Task Network planner.
    
    Takes a high-level goal (e.g., "full_assessment") and decomposes
    it into an ordered sequence of primitive tasks that agents can execute.
    """

    def __init__(self):
        self._methods = {m.compound_task: m for m in METHODS}
        self._primitives = PRIMITIVES

    def plan(self, goal: str, target: str,
             scope_directives: Optional[List[str]] = None) -> List[HTNTask]:
        """
        Decompose a goal into executable primitive tasks.
        
        Args:
            goal: High-level goal name (e.g., "full_assessment")
            target: Target to scan
            scope_directives: Optional scope-based constraints
            
        Returns:
            Ordered list of primitive HTNTask objects
        """
        root = HTNTask(
            name=goal, task_type="compound",
            parameters={"target": target},
        )

        primitives = self._decompose(root, scope_directives or [])
        logger.info(f"📋 HTN: '{goal}' → {len(primitives)} primitive tasks")
        return primitives

    def _decompose(self, task: HTNTask,
                   directives: List[str]) -> List[HTNTask]:
        """Recursively decompose compound tasks into primitives."""
        # Check if this is already a primitive
        if task.name in self._primitives:
            prim_info = self._primitives[task.name]

            # Check scope directives (e.g., DISABLE:fuzzing)
            for d in directives:
                if d.startswith("DISABLE:"):
                    disabled = d.split(":")[1].lower()
                    if disabled in task.name.lower():
                        logger.info(f"⏭️ Skipping {task.name} (disabled by scope)")
                        return []

            return [HTNTask(
                name=task.name,
                task_type="primitive",
                agent_type=prim_info.get("agent", ""),
                parameters={
                    **task.parameters,
                    "tool": prim_info.get("tool"),
                    "vuln_class": prim_info.get("vuln_class"),
                },
                estimated_duration_s=prim_info.get("timeout", 30),
            )]

        # Look up decomposition method
        method = self._methods.get(task.name)
        if not method:
            logger.warning(f"No decomposition method for: {task.name}")
            return [task]  # Return as-is

        # Decompose into subtasks
        primitives = []
        for subtask_name in method.subtask_names:
            subtask = HTNTask(
                name=subtask_name,
                task_type="compound",
                parameters=task.parameters.copy(),
            )
            primitives.extend(self._decompose(subtask, directives))

        return primitives

    def get_available_goals(self) -> List[str]:
        """List all available top-level goals."""
        return list(self._methods.keys())

    def get_task_info(self, task_name: str) -> Optional[Dict]:
        """Get info about a primitive task."""
        return self._primitives.get(task_name)
