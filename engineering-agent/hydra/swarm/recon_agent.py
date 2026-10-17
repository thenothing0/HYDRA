"""
╔══════════════════════════════════════════════════════════════╗
║  Recon Agent — Asset Discovery & Endpoint Mapping           ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.agent.recon")


class ReconAgent(BaseAgent):
    AGENT_TYPE = "recon"
    AGENT_NAME = "Recon Agent"
    
    def __init__(self, bus: MemoryBus, mcp_client=None):
        super().__init__(bus)
        self.mcp = mcp_client
    
    async def execute(self, task: Task) -> Dict[str, Any]:
        handlers = {
            "subdomain_enum": self._subdomain_enum,
            "http_probe": self._http_probe,
            "endpoint_discovery": self._endpoint_discovery,
        }
        handler = handlers.get(task.task_type)
        if not handler:
            raise ValueError(f"Unknown task type: {task.task_type}")
        return await handler(task)
    
    async def _subdomain_enum(self, task: Task) -> Dict[str, Any]:
        target = task.payload["target"]
        self.logger.info(f"Enumerating subdomains for: {target}")
        subdomains = set()
        
        for tool in ["subfinder", "amass"]:
            try:
                result = await self.mcp.execute_tool("subdomain_enum", {
                    "target": target, "tool": tool,
                })
                if result.get("success"):
                    for line in result.get("output", "").strip().split("\n"):
                        line = line.strip()
                        if line and "." in line:
                            subdomains.add(line.lower())
            except Exception as e:
                self.logger.warning(f"{tool} failed: {e}")
        
        subdomain_list = sorted(subdomains)
        await self.bus.set_state(
            f"assets:{task.payload.get('scan_id')}:subdomains", subdomain_list
        )
        return {"task_type": "subdomain_enum", "target": target,
                "subdomains": subdomain_list, "count": len(subdomain_list)}
    
    async def _http_probe(self, task: Task) -> Dict[str, Any]:
        target = task.payload["target"]
        context = task.payload.get("context", {})
        hosts = context.get("recon", [{}])
        subdomains = []
        for r in hosts:
            if isinstance(r, dict):
                subdomains.extend(r.get("subdomains", []))
        if not subdomains:
            subdomains = [target]
        
        live_hosts = []
        batch_size = 50
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            try:
                result = await self.mcp.execute_tool("http_probe", {
                    "targets": batch, "tool": "httpx",
                })
                if result.get("success"):
                    for line in result.get("output", "").strip().split("\n"):
                        line = line.strip()
                        if line and line.startswith("http"):
                            live_hosts.append(line)
            except Exception as e:
                self.logger.warning(f"httpx probe failed: {e}")
        
        return {"task_type": "http_probe", "target": target,
                "live_hosts": live_hosts, "count": len(live_hosts)}
    
    async def _endpoint_discovery(self, task: Task) -> Dict[str, Any]:
        target = task.payload["target"]
        endpoints = set()
        
        for tool in ["katana", "gau"]:
            try:
                result = await self.mcp.execute_tool("endpoint_discovery", {
                    "target": target, "tool": tool,
                })
                if result.get("success"):
                    for line in result.get("output", "").strip().split("\n"):
                        if line.strip():
                            endpoints.add(line.strip())
            except Exception as e:
                self.logger.warning(f"{tool} failed: {e}")
        
        return {"task_type": "endpoint_discovery", "target": target,
                "endpoints": sorted(endpoints), "count": len(endpoints)}
