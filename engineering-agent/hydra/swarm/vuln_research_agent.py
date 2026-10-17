"""
╔══════════════════════════════════════════════════════════════╗
║  Vulnerability Research Agent — Vuln Classification & CVE   ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.agent.vuln_research")


class VulnResearchAgent(BaseAgent):
    AGENT_TYPE = "vuln_research"
    AGENT_NAME = "Vulnerability Research Agent"
    
    def __init__(self, bus: MemoryBus, mcp_client=None, ai_router=None):
        super().__init__(bus)
        self.mcp = mcp_client
        self.ai = ai_router
    
    async def execute(self, task: Task) -> Dict[str, Any]:
        handlers = {
            "vuln_scan": self._vuln_scan,
            "tech_detection": self._tech_detection,
            "cve_lookup": self._cve_lookup,
        }
        handler = handlers.get(task.task_type)
        if not handler:
            raise ValueError(f"Unknown task type: {task.task_type}")
        return await handler(task)
    
    async def _vuln_scan(self, task: Task) -> Dict[str, Any]:
        """Run Nuclei vulnerability scan against discovered hosts."""
        target = task.payload["target"]
        context = task.payload.get("context", {})
        
        # Get live hosts from recon phase
        live_hosts = []
        for r in context.get("recon", []):
            if isinstance(r, dict):
                live_hosts.extend(r.get("live_hosts", []))
        if not live_hosts:
            live_hosts = [target if target.startswith("http") else f"https://{target}"]
        
        findings = []
        for host in live_hosts[:100]:  # cap to prevent runaway
            try:
                result = await self.mcp.execute_tool("nuclei_scan", {
                    "target": host,
                    "severity": "low,medium,high,critical",
                })
                if result.get("success") and result.get("output"):
                    parsed = self._parse_nuclei_output(result["output"])
                    findings.extend(parsed)
            except Exception as e:
                self.logger.warning(f"Nuclei scan failed for {host}: {e}")
        
        self.logger.info(f"Found {len(findings)} potential vulnerabilities")
        return {"task_type": "vuln_scan", "target": target,
                "findings": findings, "count": len(findings)}
    
    def _parse_nuclei_output(self, output: str) -> list:
        """Parse Nuclei JSON/text output into structured findings."""
        import json
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                })
            except json.JSONDecodeError:
                # Plain text output — extract what we can
                if "[" in line and "]" in line:
                    findings.append({"raw": line, "severity": "info"})
        return findings
    
    async def _tech_detection(self, task: Task) -> Dict[str, Any]:
        """Detect technologies running on the target."""
        target = task.payload["target"]
        technologies = []
        
        try:
            result = await self.mcp.execute_tool("tech_detect", {
                "target": target, "tool": "whatweb",
            })
            if result.get("success"):
                technologies = self._parse_tech_output(result["output"])
        except Exception as e:
            self.logger.warning(f"Tech detection failed: {e}")
        
        return {"task_type": "tech_detection", "target": target,
                "technologies": technologies}
    
    def _parse_tech_output(self, output: str) -> list:
        techs = []
        for line in output.strip().split("\n"):
            if line.strip():
                techs.append(line.strip())
        return techs
    
    async def _cve_lookup(self, task: Task) -> Dict[str, Any]:
        """Use AI to map findings to known CVEs."""
        target = task.payload["target"]
        context = task.payload.get("context", {})
        
        # Collect technologies and findings for CVE mapping
        techs = []
        findings = []
        for r in context.get("analysis", context.get("recon", [])):
            if isinstance(r, dict):
                techs.extend(r.get("technologies", []))
                findings.extend(r.get("findings", []))
        
        # 1) Real exploit intelligence: enrich any findings that carry a CVE
        #    with authoritative public data (CISA KEV + NVD refs). This is the
        #    ground truth — no guessing, no exploitation.
        exploit_intel: list = []
        known_exploited: list = []
        try:
            from hydra.exploits import ExploitIntel, extract_cves
            intel = ExploitIntel()
            await intel.enrich_findings(findings)
            for f in findings:
                for block in f.get("exploit_intel", []):
                    exploit_intel.append(block)
                    if block.get("known_exploited"):
                        known_exploited.append(block["cve_id"])
        except Exception as e:
            self.logger.warning(f"Exploit-intel enrichment failed: {e}")

        # 2) Optional AI mapping for techs where no CVE was matched directly.
        cve_mappings = []
        if self.ai and (techs or findings):
            prompt = (
                f"Given these technologies: {techs[:20]}\n"
                f"And these findings: {[f.get('name','') for f in findings[:20]]}\n"
                "List relevant CVEs with severity ratings. "
                "Return JSON array of objects with: cve_id, description, severity, affected_component"
            )
            try:
                ai_result = await self.ai.query(prompt, task_type="cve_mapping")
                if ai_result:
                    import json
                    try:
                        cve_mappings = json.loads(ai_result)
                    except json.JSONDecodeError:
                        cve_mappings = [{"raw_analysis": ai_result}]
            except Exception as e:
                self.logger.warning(f"AI CVE lookup failed: {e}")

        return {"task_type": "cve_lookup", "target": target,
                "cve_mappings": cve_mappings,
                "exploit_intel": exploit_intel,
                "known_exploited": known_exploited,
                "findings": findings}
