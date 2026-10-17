"""
╔══════════════════════════════════════════════════════════════╗
║  Specialized Agents — Domain-Specific Security Agents       ║
╚══════════════════════════════════════════════════════════════╝

Domain specialists spawned on demand alongside the standard pipeline. Each is a
``BaseAgent`` keyed by its ``AGENT_TYPE`` and resolved through
``hydra.swarm.registry``.
"""

from hydra.swarm.specialized.api_agent import APISecurityAgent
from hydra.swarm.specialized.cloud_agent import CloudSecurityAgent
from hydra.swarm.specialized.web3_agent import Web3SecurityAgent
from hydra.swarm.specialized.mobile_agent import MobileSecurityAgent

__all__ = [
    "APISecurityAgent",
    "CloudSecurityAgent",
    "Web3SecurityAgent",
    "MobileSecurityAgent",
]

