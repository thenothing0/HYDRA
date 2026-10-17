"""
╔══════════════════════════════════════════════════════════════╗
║  Pre-built Workflow Templates — Ready-to-use Scan Profiles  ║
║  quick_recon | full_bounty | api_only | web3_audit | etc.   ║
╚══════════════════════════════════════════════════════════════╝
"""

from typing import Any, Dict, List


WORKFLOWS: Dict[str, Dict[str, Any]] = {
    "quick_recon": {
        "name": "Quick Reconnaissance",
        "description": "Fast subdomain enumeration + tech fingerprinting + port scan",
        "estimated_duration": "5 min",
        "phases": [
            {"phase": "subdomain_enum", "agent_type": "recon",
             "tools": ["subfinder"], "priority": 0},
            {"phase": "http_probe", "agent_type": "recon",
             "tools": ["httpx"], "priority": 1},
            {"phase": "tech_detect", "agent_type": "recon",
             "tools": ["whatweb"], "priority": 2},
            {"phase": "port_scan", "agent_type": "recon",
             "tools": ["nmap"], "priority": 2},
        ],
        "skip_phases": ["exploit_hypothesis", "validation"],
        "nuclei_severity": "high,critical",
        "max_concurrent": 3,
    },
    "full_bounty": {
        "name": "Full Bug Bounty Assessment",
        "description": "Complete recon → hunt → validate → report pipeline",
        "estimated_duration": "30 min",
        "phases": [
            {"phase": "subdomain_enum", "agent_type": "recon",
             "tools": ["subfinder", "amass"], "priority": 0},
            {"phase": "http_probe", "agent_type": "recon",
             "tools": ["httpx"], "priority": 1},
            {"phase": "url_discovery", "agent_type": "recon",
             "tools": ["katana", "gau"], "priority": 1},
            {"phase": "tech_detect", "agent_type": "recon",
             "tools": ["whatweb", "wafw00f"], "priority": 2},
            {"phase": "dir_brute", "agent_type": "recon",
             "tools": ["ffuf", "dirsearch"], "priority": 2},
            {"phase": "port_scan", "agent_type": "recon",
             "tools": ["nmap"], "priority": 2},
            {"phase": "vuln_scan", "agent_type": "vuln_research",
             "tools": ["nuclei"], "priority": 3},
            {"phase": "exploit_hypothesis", "agent_type": "exploit_hypothesis",
             "tools": [], "priority": 4},
            {"phase": "hunt_loop", "agent_type": "hunt",
             "vuln_classes": ["ssrf", "idor", "authz", "xss"],
             "priority": 4},
            {"phase": "chain_building", "agent_type": "chain_builder",
             "priority": 5},
            {"phase": "validation", "agent_type": "validation",
             "tools": [], "priority": 6},
            {"phase": "reporting", "agent_type": "reporting",
             "tools": [], "priority": 7},
        ],
        "nuclei_severity": "low,medium,high,critical",
        "max_concurrent": 5,
        "enable_consensus": True,
        "enable_hunt_loops": True,
        "enable_chain_building": True,
    },
    "api_only": {
        "name": "API Security Assessment",
        "description": "API endpoint discovery + auth testing + parameter fuzzing",
        "estimated_duration": "15 min",
        "phases": [
            {"phase": "api_discovery", "agent_type": "recon",
             "tools": ["katana", "httpx"], "priority": 0},
            {"phase": "api_fingerprint", "agent_type": "recon",
             "tools": ["whatweb"], "priority": 1},
            {"phase": "api_fuzz", "agent_type": "vuln_research",
             "tools": ["ffuf", "nuclei"], "priority": 2,
             "nuclei_tags": ["api", "graphql", "jwt", "oauth"]},
            {"phase": "auth_testing", "agent_type": "vuln_research",
             "tools": ["nuclei"], "priority": 3,
             "nuclei_tags": ["auth-bypass", "idor", "token"]},
            {"phase": "hunt_loop", "agent_type": "hunt",
             "vuln_classes": ["idor", "authz", "oauth", "ssrf"],
             "priority": 4},
            {"phase": "validation", "agent_type": "validation",
             "tools": [], "priority": 5},
            {"phase": "reporting", "agent_type": "reporting",
             "tools": [], "priority": 6},
        ],
        "nuclei_severity": "medium,high,critical",
        "max_concurrent": 4,
        "specialized_agent": "api",
    },
    "web3_audit": {
        "name": "Web3 / Smart Contract Audit",
        "description": "Solidity/Vyper analysis for DeFi vulnerabilities",
        "estimated_duration": "20 min",
        "phases": [
            {"phase": "contract_analysis", "agent_type": "web3",
             "tools": [], "priority": 0,
             "checks": ["reentrancy", "flash_loan", "oracle_manipulation",
                        "access_control", "integer_overflow"]},
            {"phase": "token_analysis", "agent_type": "web3",
             "tools": [], "priority": 1,
             "checks": ["erc20_compliance", "approval_flow",
                        "transfer_restrictions"]},
            {"phase": "defi_patterns", "agent_type": "web3",
             "tools": [], "priority": 2,
             "checks": ["price_manipulation", "sandwich_attack",
                        "governance_attack"]},
            {"phase": "reporting", "agent_type": "reporting",
             "tools": [], "priority": 3},
        ],
        "nuclei_severity": "medium,high,critical",
        "max_concurrent": 2,
        "specialized_agent": "web3",
    },
    "blackbox": {
        "name": "Black-Box Testing",
        "description": "No source code — pure external testing with aggressive recon",
        "estimated_duration": "25 min",
        "phases": [
            {"phase": "subdomain_enum", "agent_type": "recon",
             "tools": ["subfinder", "amass"], "priority": 0},
            {"phase": "http_probe", "agent_type": "recon",
             "tools": ["httpx"], "priority": 1},
            {"phase": "url_discovery", "agent_type": "recon",
             "tools": ["katana", "gau"], "priority": 1},
            {"phase": "dir_brute", "agent_type": "recon",
             "tools": ["ffuf", "dirsearch"], "priority": 2},
            {"phase": "vuln_scan", "agent_type": "vuln_research",
             "tools": ["nuclei"], "priority": 3},
            {"phase": "hunt_loop", "agent_type": "hunt",
             "vuln_classes": ["ssrf", "idor", "xss", "sqli",
                              "info_disclosure", "open_redirect"],
             "priority": 4},
            {"phase": "chain_building", "agent_type": "chain_builder",
             "priority": 5},
            {"phase": "validation", "agent_type": "validation",
             "tools": [], "priority": 6},
            {"phase": "reporting", "agent_type": "reporting",
             "tools": [], "priority": 7},
        ],
        "nuclei_severity": "low,medium,high,critical",
        "max_concurrent": 5,
        "mode": "aggressive",
    },
    "code_review": {
        "name": "Source Code Security Review",
        "description": "Static analysis of source code for security issues",
        "estimated_duration": "15 min",
        "phases": [
            {"phase": "static_analysis", "agent_type": "vuln_research",
             "tools": [], "priority": 0,
             "checks": ["hardcoded_secrets", "injection_sinks",
                        "auth_bypass_patterns", "crypto_misuse",
                        "path_traversal_patterns"]},
            {"phase": "dependency_check", "agent_type": "vuln_research",
             "tools": [], "priority": 1,
             "checks": ["outdated_deps", "known_cves",
                        "license_issues"]},
            {"phase": "reporting", "agent_type": "reporting",
             "tools": [], "priority": 2},
        ],
        "nuclei_severity": "medium,high,critical",
        "max_concurrent": 2,
    },
}


def get_workflow(name: str) -> Dict[str, Any]:
    """Get a workflow template by name."""
    return WORKFLOWS.get(name, WORKFLOWS["full_bounty"])


def list_workflows() -> List[Dict[str, str]]:
    """List all available workflows."""
    return [
        {"name": k, "title": v["name"],
         "description": v["description"],
         "duration": v.get("estimated_duration", "?")}
        for k, v in WORKFLOWS.items()
    ]


def get_phases(workflow_name: str) -> List[Dict]:
    """Get phases for a workflow."""
    wf = WORKFLOWS.get(workflow_name, WORKFLOWS["full_bounty"])
    return wf.get("phases", [])
