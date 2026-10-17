"""
MCP Bounty Platform Server — Live API integration with bug bounty platforms.

Provides tools:
  - get_program_scope:  Fetch program scope from H1/BC/Intigriti
  - list_programs:      List available programs
  - submit_report:      Draft a submission report
  - sync_scope:         Sync scope to local policy engine

Usage:
  python -m mcp_bounty_server.server
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.mcp.bounty")


class BountyPlatformRouter:
    """Routes requests to the correct platform adapter."""

    def __init__(self):
        self._adapters = {
            "hackerone": HackerOneAdapter(),
            "bugcrowd": BugcrowdAdapter(),
            "intigriti": IntigritiAdapter(),
        }

    def get_adapter(self, platform: str):
        return self._adapters.get(platform.lower())


class HackerOneAdapter:
    """HackerOne API v1 integration."""
    BASE_URL = "https://api.hackerone.com/v1"

    async def get_program(self, program_handle: str,
                          api_user: str = "", api_token: str = "") -> Dict:
        """Fetch program details from HackerOne API."""
        import aiohttp
        auth = aiohttp.BasicAuth(api_user, api_token) if api_user else None
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/hackers/programs/{program_handle}",
                auth=auth,
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"error": f"HTTP {resp.status}", "platform": "hackerone"}

    async def get_scope(self, program_handle: str,
                        api_user: str = "", api_token: str = "") -> Dict:
        """Fetch program scope assets."""
        data = await self.get_program(program_handle, api_user, api_token)
        if "error" in data:
            return data
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "platform": "hackerone",
            "program": program_handle,
            "in_scope": self._extract_scope(data, eligible=True),
            "out_of_scope": self._extract_scope(data, eligible=False),
            "policy": attributes.get("policy", ""),
        }

    def _extract_scope(self, data: Dict, eligible: bool) -> List[Dict]:
        assets = []
        relationships = data.get("data", {}).get("relationships", {})
        structured_scopes = relationships.get("structured_scopes", {}).get("data", [])
        for scope in structured_scopes:
            attrs = scope.get("attributes", {})
            if attrs.get("eligible_for_bounty", False) == eligible:
                assets.append({
                    "identifier": attrs.get("asset_identifier", ""),
                    "type": attrs.get("asset_type", ""),
                    "instruction": attrs.get("instruction", ""),
                })
        return assets


class BugcrowdAdapter:
    """Bugcrowd API integration."""
    BASE_URL = "https://api.bugcrowd.com"

    async def get_scope(self, program_code: str,
                        api_token: str = "") -> Dict:
        import aiohttp
        headers = {"Authorization": f"Token {api_token}"} if api_token else {}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/programs/{program_code}",
                headers=headers,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"platform": "bugcrowd", "program": program_code, "data": data}
                return {"error": f"HTTP {resp.status}", "platform": "bugcrowd"}


class IntigritiAdapter:
    """Intigriti API integration."""
    BASE_URL = "https://api.intigriti.com/core"

    async def get_scope(self, program_id: str,
                        api_token: str = "") -> Dict:
        import aiohttp
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.BASE_URL}/programs/{program_id}",
                headers=headers,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"platform": "intigriti", "program": program_id, "data": data}
                return {"error": f"HTTP {resp.status}", "platform": "intigriti"}


# ═══════════════════════════════════════════
#  MCP Tool Definitions
# ═══════════════════════════════════════════

TOOL_DEFINITIONS = [
    {
        "name": "get_program_scope",
        "description": "Fetch bug bounty program scope from H1/Bugcrowd/Intigriti",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "enum": ["hackerone", "bugcrowd", "intigriti"]},
                "program": {"type": "string", "description": "Program handle/code"},
                "api_token": {"type": "string", "description": "API token (optional)"},
            },
            "required": ["platform", "program"],
        },
    },
    {
        "name": "list_programs",
        "description": "List available programs on a bounty platform",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string"},
                "api_token": {"type": "string"},
            },
            "required": ["platform"],
        },
    },
    {
        "name": "draft_report",
        "description": "Draft a bug bounty submission report",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {"type": "object", "description": "Finding data"},
                "platform": {"type": "string"},
                "template": {"type": "string", "default": "standard"},
            },
            "required": ["finding"],
        },
    },
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps({"tools": TOOL_DEFINITIONS}, indent=2))
    print("Bounty Platform MCP Server ready")
