"""
╔══════════════════════════════════════════════════════════════╗
║  Agent Factory — Dynamic Agent Spawning                     ║
║  Creates specialized agents on-the-fly based on target type ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict, List, Optional, Type

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus

logger = logging.getLogger("hydra.swarm.factory")


# Target type detection heuristics
TARGET_SIGNATURES = {
    "api": {
        "indicators": ["/api/", "/v1/", "/v2/", "/graphql", "/rest/",
                       "api.", "swagger", "openapi", ".json", "/docs"],
        "content_types": ["application/json", "application/xml"],
        "agent_type": "api",
    },
    "web3": {
        "indicators": [".sol", ".vy", "contract", "ethereum", "polygon",
                       "0x", "defi", "token", "nft", "web3"],
        "extensions": [".sol", ".vy"],
        "agent_type": "web3",
    },
    "mobile": {
        "indicators": [".apk", ".ipa", ".aab", "android", "ios",
                       "mobile", "app-release"],
        "extensions": [".apk", ".ipa", ".aab"],
        "agent_type": "mobile",
    },
    "cloud": {
        "indicators": ["amazonaws.com", "azure", "googleapis.com",
                       "cloudfront", "s3.", "blob.core", "cloud",
                       "bucket", "lambda", "function"],
        "agent_type": "cloud",
    },
    "web": {
        "indicators": ["http", "www.", ".com", ".org", ".net", ".io"],
        "agent_type": "web",
    },
}


class AgentSpec:
    """Specification for a dynamically created agent."""
    def __init__(self, agent_type: str, target_type: str,
                 tools: List[str], nuclei_tags: List[str],
                 priority_checks: List[str], workflow_hints: List[str]):
        self.agent_type = agent_type
        self.target_type = target_type
        self.tools = tools
        self.nuclei_tags = nuclei_tags
        self.priority_checks = priority_checks
        self.workflow_hints = workflow_hints


# Pre-defined specs for specialized agents
AGENT_SPECS = {
    "api": AgentSpec(
        agent_type="api_specialist",
        target_type="api",
        tools=["nuclei", "ffuf", "httpx", "katana"],
        nuclei_tags=["api", "graphql", "jwt", "oauth", "idor"],
        priority_checks=[
            "broken_auth", "idor", "mass_assignment",
            "rate_limiting", "injection", "ssrf",
            "jwt_weakness", "graphql_introspection",
        ],
        workflow_hints=[
            "Enumerate all API endpoints",
            "Test authentication flows",
            "Check authorization on every endpoint",
            "Fuzz parameters for injection",
            "Test rate limiting",
            "Check for mass assignment",
        ],
    ),
    "web3": AgentSpec(
        agent_type="web3_specialist",
        target_type="web3",
        tools=["nuclei"],
        nuclei_tags=["web3", "blockchain"],
        priority_checks=[
            "reentrancy", "flash_loan", "oracle_manipulation",
            "access_control", "integer_overflow", "front_running",
            "unchecked_return", "delegatecall", "selfdestruct",
            "tx_origin", "block_timestamp",
        ],
        workflow_hints=[
            "Analyze contract for reentrancy",
            "Check access control modifiers",
            "Review token approval flows",
            "Analyze flash loan attack vectors",
            "Check oracle price manipulation",
        ],
    ),
    "mobile": AgentSpec(
        agent_type="mobile_specialist",
        target_type="mobile",
        tools=["nuclei"],
        nuclei_tags=["mobile", "android", "ios"],
        priority_checks=[
            "insecure_storage", "hardcoded_secrets",
            "certificate_pinning", "root_detection_bypass",
            "exported_components", "deep_link_abuse",
            "webview_vuln", "insecure_communication",
        ],
        workflow_hints=[
            "Decompile and analyze APK/IPA",
            "Search for hardcoded secrets",
            "Check certificate pinning",
            "Analyze exported components",
            "Test deep link handling",
        ],
    ),
    "cloud": AgentSpec(
        agent_type="cloud_specialist",
        target_type="cloud",
        tools=["nuclei", "httpx", "nmap"],
        nuclei_tags=["cloud", "aws", "azure", "gcp", "s3"],
        priority_checks=[
            "open_s3_bucket", "exposed_metadata",
            "misconfigured_cors", "subdomain_takeover",
            "exposed_credentials", "public_snapshots",
            "overprivileged_iam", "unencrypted_storage",
        ],
        workflow_hints=[
            "Check S3/blob storage permissions",
            "Test metadata endpoints",
            "Enumerate cloud services",
            "Check for subdomain takeover",
            "Test IAM misconfigurations",
        ],
    ),
}


class AgentFactory:
    """
    Dynamic Agent Factory.
    
    Detects target type and spawns specialized agents
    with domain-specific knowledge and tooling.
    """

    def __init__(self, bus: MemoryBus, mcp_client=None, ai_router=None):
        self.bus = bus
        self.mcp = mcp_client
        self.ai = ai_router
        self._spawned: Dict[str, Dict] = {}

    def detect_target_type(self, target: str) -> str:
        """Detect target type from URL/path patterns."""
        target_lower = target.lower()
        scores = {}
        for ttype, sig in TARGET_SIGNATURES.items():
            score = sum(1 for ind in sig["indicators"] if ind in target_lower)
            if "extensions" in sig:
                score += sum(2 for ext in sig["extensions"] if target_lower.endswith(ext))
            scores[ttype] = score

        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return "web"  # Default
        logger.info(f"🎯 Target type detected: {best} (score: {scores[best]})")
        return best

    def get_spec(self, target: str) -> AgentSpec:
        """Get agent spec for a target."""
        target_type = self.detect_target_type(target)
        return AGENT_SPECS.get(target_type, AGENT_SPECS["api"])

    def spawn_specialized_agent(self, target: str) -> Dict[str, Any]:
        """Spawn a specialized agent based on target type."""
        target_type = self.detect_target_type(target)
        spec = AGENT_SPECS.get(target_type)

        if not spec:
            logger.info(f"No specialized agent for type '{target_type}' — using defaults")
            return {"agent_type": "generic", "spec": None, "spawned": False}

        spawn_info = {
            "agent_type": spec.agent_type,
            "target_type": target_type,
            "tools": spec.tools,
            "nuclei_tags": spec.nuclei_tags,
            "priority_checks": spec.priority_checks,
            "workflow_hints": spec.workflow_hints,
            "spawned": True,
        }

        self._spawned[target] = spawn_info
        logger.info(
            f"🐝 Spawned {spec.agent_type} for {target} "
            f"({len(spec.priority_checks)} checks, {len(spec.tools)} tools)"
        )
        return spawn_info

    def get_workflow_hints(self, target: str) -> List[str]:
        """Get workflow recommendations for a target."""
        spec = self.get_spec(target)
        return spec.workflow_hints

    def get_nuclei_tags(self, target: str) -> List[str]:
        """Get nuclei template tags for a target."""
        spec = self.get_spec(target)
        return spec.nuclei_tags

    def get_priority_checks(self, target: str) -> List[str]:
        """Get priority vulnerability checks for a target."""
        spec = self.get_spec(target)
        return spec.priority_checks

    def get_spawned_agents(self) -> Dict[str, Dict]:
        return dict(self._spawned)
