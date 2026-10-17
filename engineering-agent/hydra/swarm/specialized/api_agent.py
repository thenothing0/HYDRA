"""
╔══════════════════════════════════════════════════════════════╗
║  API Security Agent — Specialized for REST/GraphQL/gRPC     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.agent.api")


class APISecurityAgent(BaseAgent):
    AGENT_TYPE = "api_specialist"
    AGENT_NAME = "API Security Agent"

    def __init__(self, bus: MemoryBus, mcp_client=None):
        super().__init__(bus)
        self.mcp = mcp_client

    PRIORITY_CHECKS = [
        "broken_auth", "idor", "mass_assignment", "rate_limiting",
        "injection", "ssrf", "jwt_weakness", "graphql_introspection",
        "excessive_data_exposure", "lack_of_resources_limiting",
        "broken_function_auth", "unrestricted_resource_consumption",
    ]

    NUCLEI_TAGS = ["api", "graphql", "jwt", "oauth", "idor", "swagger"]

    API_DISCOVERY_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/__graphql",
        "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/swagger-ui/", "/redoc", "/api-docs",
        "/grpc", "/.well-known/openid-configuration",
    ]

    async def execute(self, task: Task) -> Dict[str, Any]:
        target = task.payload.get("target", "")
        self.logger.info(f"🔌 API analysis: {target}")

        results = {
            "agent": self.AGENT_TYPE,
            "target": target,
            "api_endpoints": [],
            "findings": [],
            "checks_performed": [],
        }

        # Phase 1: API endpoint discovery
        if self.mcp:
            for path in self.API_DISCOVERY_PATHS:
                resp = await self.mcp.execute_tool(
                    "http_probe", {"target": f"{target}{path}", "timeout": 10}
                )
                if resp.get("success") and "200" in str(resp.get("output", "")):
                    results["api_endpoints"].append(path)

            # Phase 2: Nuclei scan with API-specific templates
            scan = await self.mcp.execute_tool("nuclei_scan", {
                "target": target,
                "tags": ",".join(self.NUCLEI_TAGS),
                "severity": "medium,high,critical",
            })
            if scan.get("success") and scan.get("output"):
                results["findings"].append({
                    "source": "nuclei", "raw": scan["output"][:2000]
                })

        results["checks_performed"] = self.PRIORITY_CHECKS
        return results
