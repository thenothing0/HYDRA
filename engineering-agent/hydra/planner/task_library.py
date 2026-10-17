"""
╔══════════════════════════════════════════════════════════════╗
║  Task Library — Reusable Task Templates for the Planner     ║
╚══════════════════════════════════════════════════════════════╝
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TaskTemplate:
    """Reusable task template for the planner."""
    name: str
    description: str
    agent_type: str
    task_type: str = "scan"
    tools: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    timeout: int = 120
    retryable: bool = True
    max_retries: int = 2


TASK_LIBRARY: Dict[str, TaskTemplate] = {
    "subdomain_enumeration": TaskTemplate(
        name="Subdomain Enumeration",
        description="Discover subdomains using passive and active sources",
        agent_type="recon",
        tools=["subfinder", "amass"],
        outputs=["subdomains"],
        timeout=180,
    ),
    "http_probing": TaskTemplate(
        name="HTTP Probing",
        description="Check which subdomains are alive and collect status codes",
        agent_type="recon",
        tools=["httpx"],
        preconditions=["subdomains"],
        outputs=["live_hosts"],
        timeout=120,
    ),
    "technology_detection": TaskTemplate(
        name="Technology Detection",
        description="Identify web technologies, frameworks, and CMS",
        agent_type="recon",
        tools=["whatweb", "wappalyzer"],
        preconditions=["live_hosts"],
        outputs=["tech_stack"],
        timeout=60,
    ),
    "port_scanning": TaskTemplate(
        name="Port Scanning",
        description="Discover open ports and services",
        agent_type="recon",
        tools=["nmap"],
        preconditions=["live_hosts"],
        outputs=["open_ports"],
        timeout=300,
    ),
    "url_discovery": TaskTemplate(
        name="URL Discovery",
        description="Crawl and discover URLs, endpoints, parameters",
        agent_type="recon",
        tools=["katana", "gau", "waybackurls"],
        preconditions=["live_hosts"],
        outputs=["urls", "parameters"],
        timeout=180,
    ),
    "directory_bruteforce": TaskTemplate(
        name="Directory Bruteforce",
        description="Discover hidden directories and files",
        agent_type="recon",
        tools=["ffuf", "dirsearch"],
        preconditions=["live_hosts"],
        outputs=["directories"],
        timeout=300,
    ),
    "nuclei_vulnerability_scan": TaskTemplate(
        name="Nuclei Vulnerability Scan",
        description="Scan for known vulnerabilities using templates",
        agent_type="vuln_research",
        tools=["nuclei"],
        preconditions=["live_hosts"],
        outputs=["vulnerabilities"],
        timeout=600,
    ),
    "parameter_fuzzing": TaskTemplate(
        name="Parameter Fuzzing",
        description="Fuzz parameters for injection vulnerabilities",
        agent_type="vuln_research",
        tools=["ffuf"],
        preconditions=["urls", "parameters"],
        outputs=["injection_points"],
        timeout=300,
    ),
    "exploit_hypothesis": TaskTemplate(
        name="Exploit Hypothesis Generation",
        description="AI-driven exploit path analysis",
        agent_type="exploit_hypothesis",
        preconditions=["vulnerabilities"],
        outputs=["exploit_chains"],
        timeout=120,
    ),
    "finding_validation": TaskTemplate(
        name="Finding Validation",
        description="Validate findings with HTTP replay and evidence",
        agent_type="validation",
        preconditions=["vulnerabilities"],
        outputs=["validated_findings"],
        timeout=180,
    ),
    "consensus_voting": TaskTemplate(
        name="Consensus Voting",
        description="Multi-agent voting on finding validity",
        agent_type="validation",
        preconditions=["validated_findings"],
        outputs=["consensus_results"],
        timeout=60,
    ),
    "report_generation": TaskTemplate(
        name="Report Generation",
        description="Generate bug bounty submission report",
        agent_type="reporting",
        preconditions=["validated_findings"],
        outputs=["report"],
        timeout=120,
    ),
    "api_endpoint_discovery": TaskTemplate(
        name="API Endpoint Discovery",
        description="Discover REST/GraphQL API endpoints",
        agent_type="api_specialist",
        tools=["katana", "httpx"],
        outputs=["api_endpoints"],
        timeout=120,
    ),
    "smart_contract_analysis": TaskTemplate(
        name="Smart Contract Analysis",
        description="Analyze Solidity/Vyper contracts for vulnerabilities",
        agent_type="web3_specialist",
        outputs=["contract_findings"],
        timeout=180,
    ),
    "s3_bucket_enumeration": TaskTemplate(
        name="S3 Bucket Enumeration",
        description="Discover and test S3/cloud storage buckets",
        agent_type="cloud_specialist",
        outputs=["bucket_findings"],
        timeout=120,
    ),
}


def get_template(name: str) -> Optional[TaskTemplate]:
    return TASK_LIBRARY.get(name)


def list_templates() -> List[Dict[str, str]]:
    return [{"name": k, "description": v.description, "agent": v.agent_type}
            for k, v in TASK_LIBRARY.items()]


def get_by_agent(agent_type: str) -> List[TaskTemplate]:
    return [t for t in TASK_LIBRARY.values() if t.agent_type == agent_type]
