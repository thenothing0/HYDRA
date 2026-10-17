"""
╔══════════════════════════════════════════════════════════════╗
║  Cloud Security Agent — AWS/Azure/GCP Misconfiguration      ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.agent.cloud")


class CloudSecurityAgent(BaseAgent):
    AGENT_TYPE = "cloud_specialist"
    AGENT_NAME = "Cloud Security Agent"

    def __init__(self, bus: MemoryBus, mcp_client=None):
        super().__init__(bus)
        self.mcp = mcp_client

    NUCLEI_TAGS = ["cloud", "aws", "azure", "gcp", "s3", "misconfig"]

    CHECKS = [
        "open_s3_buckets", "exposed_metadata_endpoint",
        "misconfigured_cors", "subdomain_takeover",
        "exposed_credentials", "public_snapshots",
        "overprivileged_iam", "unencrypted_storage",
        "exposed_admin_panels", "default_credentials",
        "open_elasticsearch", "exposed_docker_api",
        "kubernetes_dashboard", "exposed_firebase",
    ]

    S3_PATTERNS = [
        "{target}.s3.amazonaws.com",
        "s3.amazonaws.com/{target}",
        "{target}.s3-us-west-1.amazonaws.com",
        "{target}.s3-us-east-1.amazonaws.com",
        "{target}-backup.s3.amazonaws.com",
        "{target}-dev.s3.amazonaws.com",
        "{target}-staging.s3.amazonaws.com",
        "{target}-prod.s3.amazonaws.com",
        "{target}-assets.s3.amazonaws.com",
        "{target}-uploads.s3.amazonaws.com",
    ]

    METADATA_ENDPOINTS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://100.100.100.200/latest/meta-data/",
    ]

    TAKEOVER_CNAMES = [
        "amazonaws.com", "cloudfront.net", "heroku.com",
        "herokuapp.com", "github.io", "azurewebsites.net",
        "cloudapp.azure.com", "trafficmanager.net",
        "blob.core.windows.net", "surge.sh",
        "fastly.net", "pantheon.io", "netlify.app",
        "fly.dev", "vercel.app",
    ]

    async def execute(self, task: Task) -> Dict[str, Any]:
        target = task.payload.get("target", "")
        self.logger.info(f"☁️ Cloud analysis: {target}")

        results = {
            "agent": self.AGENT_TYPE, "target": target,
            "findings": [], "checks": self.CHECKS,
            "s3_checked": [], "takeover_candidates": [],
        }

        if self.mcp:
            # S3 bucket enumeration
            base = target.replace("https://", "").replace("http://", "").split(".")[0]
            for pattern in self.S3_PATTERNS[:5]:
                bucket_url = pattern.format(target=base)
                resp = await self.mcp.execute_tool(
                    "http_probe", {"target": f"https://{bucket_url}", "timeout": 5}
                )
                results["s3_checked"].append(bucket_url)
                if resp.get("success") and resp.get("output"):
                    output = str(resp["output"])
                    if "200" in output or "ListBucket" in output:
                        results["findings"].append({
                            "name": f"Open S3 bucket: {bucket_url}",
                            "severity": "high",
                            "type": "cloud_misconfig",
                            "confidence": 0.8,
                        })

            # Nuclei cloud templates
            scan = await self.mcp.execute_tool("nuclei_scan", {
                "target": target,
                "tags": ",".join(self.NUCLEI_TAGS),
                "severity": "medium,high,critical",
            })
            if scan.get("success") and scan.get("output"):
                results["findings"].append({
                    "source": "nuclei", "raw": scan["output"][:2000]
                })

        return results
