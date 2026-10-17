"""
╔══════════════════════════════════════════════════════════════╗
║  Swarm package — Multi-Agent Swarm Architecture              ║
╚══════════════════════════════════════════════════════════════╝

Two ways to run the swarm, one shared design:

  - ``SwarmOrchestrator`` — wires the Coordinator + every pipeline agent into a
    single process over one in-memory bus (local/dev/CI; what ``_wf_swarm`` uses).
  - ``python -m hydra.swarm`` (``node.py``) — role-aware distributed entrypoint;
    each container becomes a coordinator or a worker over a Redis-backed bus.

In both, the ``CoordinatorAgent`` is the ONLY orchestrator: it scope-gates every
target (fail-closed) before pushing tasks, and stateless ``BaseAgent`` workers
communicate solely through the ``MemoryBus``. Nothing here sends traffic — agents
call the MCP tool layer, below which the never-send guardrails live untouched.
"""

from hydra.memory.bus import MemoryBus, Task, TaskPriority, TaskStatus

from hydra.swarm.base_agent import BaseAgent
from hydra.swarm.coordinator import CoordinatorAgent
from hydra.swarm.orchestrator import SwarmOrchestrator

from hydra.swarm.recon_agent import ReconAgent
from hydra.swarm.vuln_research_agent import VulnResearchAgent
from hydra.swarm.exploit_hypothesis_agent import ExploitHypothesisAgent
from hydra.swarm.validation_agent import ValidationAgent
from hydra.swarm.reporting_agent import ReportingAgent

from hydra.swarm.specialized import (
    APISecurityAgent,
    CloudSecurityAgent,
    Web3SecurityAgent,
    MobileSecurityAgent,
)

from hydra.swarm.registry import (
    AGENT_REGISTRY,
    PIPELINE_AGENT_TYPES,
    SPECIALIST_AGENT_TYPES,
    get_agent_class,
    build_agent,
    build_agents,
)

__all__ = [
    # Bus primitives
    "MemoryBus", "Task", "TaskPriority", "TaskStatus",
    # Orchestration
    "CoordinatorAgent", "SwarmOrchestrator", "BaseAgent",
    # Pipeline agents
    "ReconAgent", "VulnResearchAgent", "ExploitHypothesisAgent",
    "ValidationAgent", "ReportingAgent",
    # Specialists
    "APISecurityAgent", "CloudSecurityAgent",
    "Web3SecurityAgent", "MobileSecurityAgent",
    # Registry / factory
    "AGENT_REGISTRY", "PIPELINE_AGENT_TYPES", "SPECIALIST_AGENT_TYPES",
    "get_agent_class", "build_agent", "build_agents",
]
