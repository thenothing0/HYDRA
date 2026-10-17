"""
╔══════════════════════════════════════════════════════════════╗
║  Exploit Chain Builder — Multi-Hop Attack Chain Construction ║
║  Safe PoC generation + chain scoring + blast radius          ║
╚══════════════════════════════════════════════════════════════╝

Builds chains like:
  subdomain → login page → SSRF → internal admin → credential leak → RCE
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.chains")


class ChainSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ChainNode:
    """Single step in an exploit chain."""
    node_id: str
    label: str
    node_type: str  # finding | asset | technique | credential
    data: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    confidence: float = 0.0
    evidence: str = ""

    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id, "label": self.label,
            "type": self.node_type, "severity": self.severity,
            "confidence": self.confidence, "evidence": self.evidence[:500],
            "data": {k: str(v)[:200] for k, v in self.data.items()},
        }


@dataclass
class ChainLink:
    """Connection between two chain nodes."""
    source_id: str
    target_id: str
    technique: str  # ssrf_pivot, cred_reuse, priv_esc, lateral_move
    description: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "source": self.source_id, "target": self.target_id,
            "technique": self.technique, "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class ExploitChain:
    """Complete multi-hop exploit chain."""
    chain_id: str
    nodes: List[ChainNode] = field(default_factory=list)
    links: List[ChainLink] = field(default_factory=list)
    overall_severity: str = "info"
    blast_radius: float = 0.0
    exploitability_score: float = 0.0
    confidence: float = 0.0
    poc_steps: List[Dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def depth(self) -> int:
        return len(self.nodes)

    @property
    def is_multi_hop(self) -> bool:
        return len(self.nodes) > 2

    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id, "depth": self.depth,
            "severity": self.overall_severity,
            "blast_radius": self.blast_radius,
            "exploitability": self.exploitability_score,
            "confidence": self.confidence,
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
            "poc_steps": self.poc_steps,
            "is_multi_hop": self.is_multi_hop,
        }


# Technique patterns for automatic chain discovery
CHAIN_PATTERNS = {
    "ssrf_to_internal": {
        "source_types": ["ssrf"],
        "target_types": ["internal_endpoint", "admin_panel", "metadata"],
        "severity_boost": 2,
        "description": "SSRF pivots to internal resource access",
    },
    "idor_to_data_leak": {
        "source_types": ["idor"],
        "target_types": ["pii", "credential", "api_key"],
        "severity_boost": 1,
        "description": "IDOR leads to sensitive data exposure",
    },
    "auth_bypass_to_admin": {
        "source_types": ["auth_bypass", "oauth_miscfg"],
        "target_types": ["admin_panel", "privileged_endpoint"],
        "severity_boost": 2,
        "description": "Authentication bypass reaches admin functionality",
    },
    "xss_to_session": {
        "source_types": ["xss", "reflected_xss", "stored_xss"],
        "target_types": ["session_token", "credential"],
        "severity_boost": 1,
        "description": "XSS enables session hijacking",
    },
    "info_disclosure_to_cred": {
        "source_types": ["info_disclosure", "exposed_config"],
        "target_types": ["credential", "api_key", "database_cred"],
        "severity_boost": 2,
        "description": "Exposed configuration reveals credentials",
    },
    "cred_to_rce": {
        "source_types": ["credential", "api_key"],
        "target_types": ["rce", "command_injection", "admin_shell"],
        "severity_boost": 3,
        "description": "Credentials enable remote code execution",
    },
    "sqli_to_data": {
        "source_types": ["sqli"],
        "target_types": ["database_dump", "credential", "pii"],
        "severity_boost": 2,
        "description": "SQL injection extracts sensitive data",
    },
    "lfi_to_rce": {
        "source_types": ["lfi", "path_traversal"],
        "target_types": ["rce", "log_poisoning"],
        "severity_boost": 3,
        "description": "Local file inclusion escalates to RCE",
    },
}

SEVERITY_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class ChainBuilder:
    """
    Builds multi-hop exploit chains from individual findings.
    
    Discovers attack paths by analyzing relationships between
    findings and computing blast radius, exploitability, and
    overall chain severity.
    """

    def __init__(self, attack_graph=None, ai_router=None):
        self.attack_graph = attack_graph
        self.ai = ai_router
        self._chains: Dict[str, ExploitChain] = {}

    def build_chains(self, findings: List[Dict], target: str = "") -> List[ExploitChain]:
        """Discover all possible exploit chains from a list of findings."""
        chains = []

        # Convert findings to chain nodes
        nodes = self._findings_to_nodes(findings)
        if len(nodes) < 2:
            return chains

        # Pattern-based chain discovery
        for pattern_name, pattern in CHAIN_PATTERNS.items():
            source_nodes = [n for n in nodes if any(
                st in n.node_type.lower() or st in n.label.lower()
                for st in pattern["source_types"]
            )]
            target_nodes = [n for n in nodes if any(
                tt in n.node_type.lower() or tt in n.label.lower()
                for tt in pattern["target_types"]
            )]

            for src in source_nodes:
                for tgt in target_nodes:
                    if src.node_id == tgt.node_id:
                        continue

                    chain = ExploitChain(
                        chain_id=self._gen_chain_id(src, tgt, pattern_name),
                        nodes=[src, tgt],
                        links=[ChainLink(
                            source_id=src.node_id, target_id=tgt.node_id,
                            technique=pattern_name,
                            description=pattern["description"],
                            confidence=min(src.confidence, tgt.confidence),
                        )],
                    )
                    chain = self._score_chain(chain, pattern)
                    chain.poc_steps = self._generate_poc(chain, target)
                    chains.append(chain)

        # Multi-hop discovery (3+ steps)
        multi_hop = self._discover_multi_hop(nodes, chains)
        chains.extend(multi_hop)

        # Sort by severity and blast radius
        chains.sort(key=lambda c: (
            SEVERITY_SCORES.get(c.overall_severity, 0),
            c.blast_radius,
        ), reverse=True)

        # Store
        for chain in chains:
            self._chains[chain.chain_id] = chain

        logger.info(f"⛓️ Built {len(chains)} exploit chains from {len(findings)} findings")
        return chains

    def _findings_to_nodes(self, findings: List[Dict]) -> List[ChainNode]:
        """Convert raw findings into chain nodes."""
        nodes = []
        for i, f in enumerate(findings):
            node = ChainNode(
                node_id=f.get("template_id", f"finding-{i}"),
                label=f.get("name", f"Finding {i}"),
                node_type=f.get("type", "unknown"),
                data=f,
                severity=f.get("severity", "info"),
                confidence=f.get("confidence_score", 0.5),
                evidence=str(f.get("evidence", f.get("matched_at", ""))),
            )
            nodes.append(node)
        return nodes

    def _discover_multi_hop(self, nodes: List[ChainNode],
                            two_hop_chains: List[ExploitChain]) -> List[ExploitChain]:
        """Find 3+ hop chains by extending existing 2-hop chains."""
        multi = []
        for chain in two_hop_chains:
            last_node = chain.nodes[-1]
            for ext_chain in two_hop_chains:
                if ext_chain.chain_id == chain.chain_id:
                    continue
                first_of_ext = ext_chain.nodes[0]
                # Can extend if last node matches first of another chain
                if (last_node.node_type == first_of_ext.node_type or
                        last_node.node_id == first_of_ext.node_id):
                    extended = ExploitChain(
                        chain_id=f"multi-{chain.chain_id}-{ext_chain.chain_id}",
                        nodes=chain.nodes + ext_chain.nodes[1:],
                        links=chain.links + ext_chain.links,
                    )
                    extended = self._score_chain(extended, {"severity_boost": 3})
                    if extended.depth <= 6:  # Cap chain depth
                        multi.append(extended)
        return multi[:20]  # Limit

    def _score_chain(self, chain: ExploitChain, pattern: Dict) -> ExploitChain:
        """Score a chain's severity, blast radius, and exploitability."""
        # Overall severity = max node severity + pattern boost
        max_sev = max(SEVERITY_SCORES.get(n.severity, 0) for n in chain.nodes)
        boost = pattern.get("severity_boost", 0)
        total = min(max_sev + boost, 4)  # Cap at critical

        sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        chain.overall_severity = sev_map.get(total, "info")

        # Blast radius = number of affected assets * chain depth
        chain.blast_radius = round(len(chain.nodes) * 0.3 + chain.depth * 0.2, 2)

        # Exploitability = average confidence * depth penalty
        avg_conf = sum(n.confidence for n in chain.nodes) / max(len(chain.nodes), 1)
        depth_penalty = 1.0 / (1 + 0.1 * chain.depth)
        chain.exploitability_score = round(avg_conf * depth_penalty, 2)

        # Chain confidence = min of all link confidences
        if chain.links:
            chain.confidence = round(
                min(l.confidence for l in chain.links) * avg_conf, 2
            )
        else:
            chain.confidence = avg_conf

        return chain

    def _generate_poc(self, chain: ExploitChain, target: str) -> List[Dict]:
        """Generate safe PoC reproduction steps."""
        steps = []
        for i, (node, link) in enumerate(zip(chain.nodes, chain.links + [None])):
            step = {
                "step": i + 1,
                "action": f"Identify: {node.label}",
                "target": node.data.get("matched_at", target),
                "evidence": node.evidence[:200] if node.evidence else "",
            }
            if link:
                step["next"] = f"Pivot via: {link.technique} → {link.description}"
            steps.append(step)
        return steps

    def _gen_chain_id(self, src: ChainNode, tgt: ChainNode, pattern: str) -> str:
        raw = f"{src.node_id}:{tgt.node_id}:{pattern}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def get_chain(self, chain_id: str) -> Optional[ExploitChain]:
        return self._chains.get(chain_id)

    def get_all_chains(self) -> List[ExploitChain]:
        return sorted(
            self._chains.values(),
            key=lambda c: SEVERITY_SCORES.get(c.overall_severity, 0),
            reverse=True,
        )

    def export_chains(self, fmt: str = "json") -> str:
        """Export all chains as JSON or markdown."""
        chains = self.get_all_chains()
        if fmt == "json":
            return json.dumps([c.to_dict() for c in chains], indent=2)
        elif fmt == "markdown":
            lines = ["# Exploit Chains\n"]
            for c in chains:
                lines.append(f"## Chain: {c.chain_id}")
                lines.append(f"**Severity**: {c.overall_severity.upper()}")
                lines.append(f"**Depth**: {c.depth} hops")
                lines.append(f"**Blast Radius**: {c.blast_radius}")
                lines.append(f"**Exploitability**: {c.exploitability_score}")
                lines.append("")
                lines.append("### Attack Path")
                path = " → ".join(n.label for n in c.nodes)
                lines.append(f"```\n{path}\n```")
                lines.append("")
                if c.poc_steps:
                    lines.append("### PoC Steps")
                    for s in c.poc_steps:
                        lines.append(f"{s['step']}. {s['action']}")
                        if s.get("next"):
                            lines.append(f"   ↳ {s['next']}")
                    lines.append("")
                lines.append("---\n")
            return "\n".join(lines)
        return ""
