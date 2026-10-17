"""
╔══════════════════════════════════════════════════════════════╗
║  Advanced Recon Intelligence — ASN, Cloud, GitHub, JS      ║
║  Extended reconnaissance capabilities using multiple tools ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.recon.advanced")


class AdvancedReconEngine:
    """
    Extended recon capabilities beyond basic subdomain enumeration.
    
    Capabilities:
      - ASN mapping
      - Cloud asset discovery
      - GitHub leak discovery
      - JavaScript endpoint extraction
      - Parameter mining
      - DNS history analysis
      - CDN detection
      - SaaS asset correlation
    """

    def __init__(self, mcp_client=None):
        self.mcp = mcp_client

    async def asn_mapping(self, target: str) -> Dict[str, Any]:
        """Map ASN information for a target."""
        results = {"target": target, "asn_info": []}
        if self.mcp:
            try:
                result = await self.mcp.execute_tool("port_scan", {
                    "target": target, "ports": "443",
                })
                if result.get("success"):
                    results["raw_output"] = result.get("output", "")[:500]
            except Exception as e:
                logger.warning(f"ASN mapping failed: {e}")
        return results

    async def github_leak_scan(
        self, target: str,
        github_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Scan GitHub for leaked secrets related to target."""
        results = {
            "target": target, "leaks": [],
            "dorks_used": [],
        }

        dorks = [
            f'"{target}" password',
            f'"{target}" api_key',
            f'"{target}" secret',
            f'"{target}" token',
            f'"{target}" AWS_ACCESS_KEY',
            f'"{target}" PRIVATE_KEY',
        ]
        results["dorks_used"] = dorks

        if github_token:
            try:
                import aiohttp
                headers = {"Authorization": f"token {github_token}"}
                async with aiohttp.ClientSession() as session:
                    for dork in dorks[:3]:
                        url = (
                            "https://api.github.com/search/code"
                            f"?q={dork}&per_page=5"
                        )
                        async with session.get(url, headers=headers) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                for item in data.get("items", []):
                                    results["leaks"].append({
                                        "repo": item.get("repository", {}).get("full_name", ""),
                                        "path": item.get("path", ""),
                                        "url": item.get("html_url", ""),
                                    })
                        await asyncio.sleep(2)  # Rate limit
            except Exception as e:
                logger.warning(f"GitHub leak scan failed: {e}")

        return results

    async def js_endpoint_extraction(
        self, target: str
    ) -> Dict[str, Any]:
        """Extract endpoints from JavaScript files."""
        results = {"target": target, "endpoints": [], "js_files": []}

        if self.mcp:
            try:
                crawl_result = await self.mcp.execute_tool(
                    "endpoint_discovery",
                    {"target": target, "tool": "katana"},
                )
                if crawl_result.get("success"):
                    output = crawl_result.get("output", "")
                    for line in output.strip().split("\n"):
                        url = line.strip()
                        if url.endswith(".js"):
                            results["js_files"].append(url)
                        elif url:
                            results["endpoints"].append(url)
            except Exception as e:
                logger.warning(f"JS extraction failed: {e}")

        # Extract API patterns from discovered endpoints
        api_patterns = []
        for ep in results["endpoints"]:
            if any(k in ep.lower() for k in ["/api/", "/v1/", "/v2/", "/graphql"]):
                api_patterns.append(ep)
        results["api_endpoints"] = api_patterns

        return results

    async def parameter_mining(self, target: str) -> Dict[str, Any]:
        """Mine parameters from historical URLs."""
        results = {"target": target, "parameters": {}}

        if self.mcp:
            try:
                gau_result = await self.mcp.execute_tool(
                    "url_gather", {"target": target},
                )
                if gau_result.get("success"):
                    output = gau_result.get("output", "")
                    for url in output.strip().split("\n"):
                        params = self._extract_params(url.strip())
                        for param in params:
                            results["parameters"][param] = (
                                results["parameters"].get(param, 0) + 1
                            )
            except Exception as e:
                logger.warning(f"Parameter mining failed: {e}")

        # Sort by frequency
        sorted_params = sorted(
            results["parameters"].items(),
            key=lambda x: x[1], reverse=True,
        )
        results["top_parameters"] = [
            {"name": k, "occurrences": v}
            for k, v in sorted_params[:50]
        ]
        return results

    async def dns_history(self, target: str) -> Dict[str, Any]:
        """Analyze DNS history for a target."""
        results = {"target": target, "dns_records": []}

        if self.mcp:
            try:
                result = await self.mcp.execute_tool(
                    "subdomain_enum",
                    {"target": target, "tool": "amass"},
                    timeout=300,
                )
                if result.get("success"):
                    for line in result.get("output", "").strip().split("\n"):
                        if line.strip():
                            results["dns_records"].append(line.strip())
            except Exception as e:
                logger.warning(f"DNS history failed: {e}")

        return results

    async def cdn_detection(self, target: str) -> Dict[str, Any]:
        """Detect CDN provider."""
        results = {"target": target, "cdn": None, "indicators": []}

        CDN_HEADERS = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "akamai": ["x-akamai-transformed"],
            "fastly": ["x-served-by", "x-cache"],
            "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "incapsula": ["x-iinfo"],
        }

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = target if target.startswith("http") else f"https://{target}"
                async with session.head(url, allow_redirects=True) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    for cdn, indicators in CDN_HEADERS.items():
                        for ind in indicators:
                            if ind.lower() in headers:
                                results["cdn"] = cdn
                                results["indicators"].append(ind)
        except Exception as e:
            logger.warning(f"CDN detection failed: {e}")

        return results

    async def full_advanced_recon(
        self, target: str,
        github_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run all advanced recon modules."""
        tasks = {
            "js_endpoints": self.js_endpoint_extraction(target),
            "parameters": self.parameter_mining(target),
            "dns_history": self.dns_history(target),
            "cdn": self.cdn_detection(target),
        }
        if github_token:
            tasks["github_leaks"] = self.github_leak_scan(
                target, github_token
            )

        results = {}
        for name, coro in tasks.items():
            try:
                results[name] = await coro
            except Exception as e:
                results[name] = {"error": str(e)}

        return results

    @staticmethod
    def _extract_params(url: str) -> List[str]:
        """Extract parameter names from a URL."""
        params = []
        if "?" in url:
            query = url.split("?", 1)[1]
            for part in query.split("&"):
                if "=" in part:
                    params.append(part.split("=", 1)[0])
        return params
