"""
╔══════════════════════════════════════════════════════════════╗
║  MCP Client — Async client for the MCP Tool Server         ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("hydra.mcp.client")


class MCPClient:
    """Client for executing tools through the MCP server."""
    
    def __init__(self, server_url: Optional[str] = None, tool_server=None):
        self.server_url = server_url
        self._tool_server = tool_server  # Direct reference for in-process mode
    
    async def execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a tool via MCP (in-process or HTTP)."""
        
        # In-process mode (same process, no HTTP overhead)
        if self._tool_server:
            return await self._tool_server.execute_tool(tool_name, dict(params), timeout)
        
        # HTTP mode (distributed)
        if self.server_url:
            return await self._http_execute(tool_name, params, timeout)
        
        return {"success": False, "error": "No MCP server configured"}
    
    async def _http_execute(
        self, tool_name: str, params: Dict, timeout: Optional[int]
    ) -> Dict[str, Any]:
        """Execute via HTTP to a remote MCP server."""
        import aiohttp
        
        payload = {"tool": tool_name, "params": params}
        if timeout:
            payload["timeout"] = timeout
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.server_url}/execute",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout or 120),
                ) as resp:
                    return await resp.json()
        except Exception as e:
            logger.error(f"MCP HTTP request failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def list_tools(self) -> Dict[str, Any]:
        """List available tools on the MCP server."""
        if self._tool_server:
            return {"tools": self._tool_server.get_available_tools()}
        
        if self.server_url:
            import aiohttp
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.server_url}/tools") as resp:
                        return await resp.json()
            except Exception as e:
                return {"error": str(e)}
        
        return {"error": "No MCP server configured"}
