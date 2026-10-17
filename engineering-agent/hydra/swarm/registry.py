"""
╔══════════════════════════════════════════════════════════════╗
║  Agent Registry — agent_type → BaseAgent class resolution   ║
║  The single source of truth for turning a task's agent_type ║
║  string into a live, correctly-constructed agent instance.  ║
╚══════════════════════════════════════════════════════════════╝

The Coordinator routes tasks by ``agent_type`` (a string on every ``Task``).
Workers — whether the single-process orchestrator or a distributed node — need
to turn that string into the right ``BaseAgent`` subclass. This module owns that
mapping and the construction logic so nothing else has to hard-code it.

Constructor signatures differ per agent (some take ``mcp_client``, some
``ai_router``, some extra engines). ``build_agent`` inspects each class's
``__init__`` and passes only the dependencies it actually accepts, so callers
can hand over the full dependency bag without knowing any agent's exact shape.
"""

import inspect
import logging
from typing import Dict, List, Optional, Type

from hydra.memory.bus import MemoryBus
from hydra.swarm.base_agent import BaseAgent

# ── Pipeline agents (the Coordinator's SCAN_PHASES) ──────────
from hydra.swarm.recon_agent import ReconAgent
from hydra.swarm.vuln_research_agent import VulnResearchAgent
from hydra.swarm.exploit_hypothesis_agent import ExploitHypothesisAgent
from hydra.swarm.validation_agent import ValidationAgent
from hydra.swarm.reporting_agent import ReportingAgent

# ── Specialized agents (domain-specific, spawned on demand) ──
from hydra.swarm.specialized.api_agent import APISecurityAgent
from hydra.swarm.specialized.cloud_agent import CloudSecurityAgent
from hydra.swarm.specialized.web3_agent import Web3SecurityAgent
from hydra.swarm.specialized.mobile_agent import MobileSecurityAgent

logger = logging.getLogger("hydra.swarm.registry")


# Every agent class known to the swarm, keyed by its AGENT_TYPE. Keyed off the
# class attribute (not a hand-typed string) so the map can never drift from the
# value the Coordinator actually routes on.
_AGENT_CLASSES: List[Type[BaseAgent]] = [
    ReconAgent,
    VulnResearchAgent,
    ExploitHypothesisAgent,
    ValidationAgent,
    ReportingAgent,
    APISecurityAgent,
    CloudSecurityAgent,
    Web3SecurityAgent,
    MobileSecurityAgent,
]

AGENT_REGISTRY: Dict[str, Type[BaseAgent]] = {
    cls.AGENT_TYPE: cls for cls in _AGENT_CLASSES
}

# The five agents that make up the standard scan pipeline, in phase order. The
# orchestrator/coordinator drive these; specialized agents join only when a
# target type calls for them.
PIPELINE_AGENT_TYPES: List[str] = [
    ReconAgent.AGENT_TYPE,
    VulnResearchAgent.AGENT_TYPE,
    ExploitHypothesisAgent.AGENT_TYPE,
    ValidationAgent.AGENT_TYPE,
    ReportingAgent.AGENT_TYPE,
]

SPECIALIST_AGENT_TYPES: List[str] = [
    APISecurityAgent.AGENT_TYPE,
    CloudSecurityAgent.AGENT_TYPE,
    Web3SecurityAgent.AGENT_TYPE,
    MobileSecurityAgent.AGENT_TYPE,
]


def get_agent_class(agent_type: str) -> Optional[Type[BaseAgent]]:
    """Return the BaseAgent subclass for an agent_type, or None if unknown."""
    return AGENT_REGISTRY.get(agent_type)


def build_agent(agent_type: str, bus: MemoryBus, **deps) -> BaseAgent:
    """
    Construct the agent for ``agent_type``, wiring in only the dependencies its
    constructor declares.

    ``deps`` is the full dependency bag (``mcp_client``, ``ai_router``,
    ``learning_engine``, ``artifact_store``, ``validation_engine``,
    ``hallucination_defense`` …). Each agent picks up the subset it accepts;
    the rest are ignored, so callers never need per-agent knowledge.

    Raises:
        KeyError: if ``agent_type`` is not in the registry.
    """
    cls = AGENT_REGISTRY.get(agent_type)
    if cls is None:
        raise KeyError(
            f"Unknown agent_type '{agent_type}'. "
            f"Known types: {sorted(AGENT_REGISTRY)}"
        )

    params = inspect.signature(cls.__init__).parameters
    accepts_kwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )
    kwargs = {
        name: value
        for name, value in deps.items()
        if accepts_kwargs or name in params
    }
    return cls(bus, **kwargs)


def build_agents(agent_types: List[str], bus: MemoryBus, **deps) -> List[BaseAgent]:
    """Construct a list of agents from their types (skips unknown, logging)."""
    agents: List[BaseAgent] = []
    for agent_type in agent_types:
        try:
            agents.append(build_agent(agent_type, bus, **deps))
        except KeyError as e:
            logger.warning(f"Skipping unknown agent type: {e}")
    return agents
