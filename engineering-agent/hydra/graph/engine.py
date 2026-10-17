"""
╔══════════════════════════════════════════════════════════════╗
║  Attack Graph Engine — Dynamic Attack Path Intelligence     ║
║  Builds and maintains a live graph of attack surfaces       ║
╚══════════════════════════════════════════════════════════════╝

Nodes: assets, services, vulnerabilities, credentials
Edges: attack transitions (e.g., SSRF → internal_access)

Example path:
  subdomain → login_page → parameter → injection → session_takeover
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("hydra.graph.engine")


@dataclass
class GraphNode:
    """A node in the attack graph."""
    id: str
    node_type: str          # asset, service, vuln, credential, endpoint
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    discovered_at: float = field(default_factory=time.time)


@dataclass
class GraphEdge:
    """A directed edge in the attack graph."""
    source_id: str
    target_id: str
    edge_type: str          # leads_to, exploits, exposes, authenticates
    label: str = ""
    weight: float = 1.0
    confidence: float = 0.5
    properties: Dict[str, Any] = field(default_factory=dict)


class AttackGraph:
    """
    Dynamic attack graph that grows as the scan progresses.
    
    Features:
      - Continuous updates from scan results
      - Path finding (shortest, highest-impact)
      - Severity propagation along paths
      - Serialization for reporting
    """
    
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[str]] = {}  # source → [targets]
        self._reverse_adj: Dict[str, List[str]] = {}  # target → [sources]
    
    def add_node(self, node: GraphNode) -> str:
        """Add or update a node in the graph."""
        self._nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        if node.id not in self._reverse_adj:
            self._reverse_adj[node.id] = []
        return node.id
    
    def add_edge(self, edge: GraphEdge):
        """Add a directed edge between two nodes."""
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            logger.warning(
                f"Edge references unknown node: {edge.source_id} → {edge.target_id}"
            )
            return
        
        self._edges.append(edge)
        self._adjacency[edge.source_id].append(edge.target_id)
        self._reverse_adj[edge.target_id].append(edge.source_id)
    
    def ingest_recon_results(self, target: str, results: Dict[str, Any]):
        """Ingest recon phase results into the graph."""
        # Root target node
        root_id = f"target:{target}"
        self.add_node(GraphNode(
            id=root_id, node_type="asset", label=target,
            properties={"role": "primary_target"},
        ))
        
        # Subdomains
        for sub in results.get("subdomains", []):
            sub_id = f"subdomain:{sub}"
            self.add_node(GraphNode(
                id=sub_id, node_type="asset", label=sub,
                properties={"asset_type": "subdomain"},
            ))
            self.add_edge(GraphEdge(
                source_id=root_id, target_id=sub_id,
                edge_type="has_subdomain", label="subdomain",
            ))
        
        # Live hosts
        for host in results.get("live_hosts", []):
            host_id = f"service:{host}"
            self.add_node(GraphNode(
                id=host_id, node_type="service", label=host,
                properties={"service_type": "http"},
            ))
            # Link to matching subdomain or root
            domain = host.replace("https://", "").replace("http://", "").split("/")[0]
            parent_id = f"subdomain:{domain}"
            if parent_id not in self._nodes:
                parent_id = root_id
            self.add_edge(GraphEdge(
                source_id=parent_id, target_id=host_id,
                edge_type="hosts_service", label="HTTP",
            ))
        
        # Endpoints
        for ep in results.get("endpoints", []):
            ep_id = f"endpoint:{hash(ep) % 100000}"
            self.add_node(GraphNode(
                id=ep_id, node_type="endpoint", label=ep[:100],
                properties={"url": ep},
            ))
    
    def ingest_vuln_results(self, results: Dict[str, Any]):
        """Ingest vulnerability scan results into the graph."""
        for finding in results.get("findings", []):
            vuln_id = f"vuln:{finding.get('template_id', hash(str(finding)) % 100000)}"
            self.add_node(GraphNode(
                id=vuln_id, node_type="vuln",
                label=finding.get("name", "Unknown"),
                severity=finding.get("severity", "info"),
                properties=finding,
            ))
            
            # Link to host
            host = finding.get("host", finding.get("matched_at", ""))
            if host:
                host_id = f"service:{host}"
                if host_id not in self._nodes:
                    self.add_node(GraphNode(
                        id=host_id, node_type="service", label=host,
                    ))
                self.add_edge(GraphEdge(
                    source_id=host_id, target_id=vuln_id,
                    edge_type="has_vulnerability", label="vulnerable",
                    confidence=finding.get("confidence_score", 0.5),
                ))
    
    def ingest_attack_chains(self, chains: List[Dict[str, Any]]):
        """Ingest theoretical attack chains into the graph."""
        for chain in chains:
            steps = chain.get("chain_steps", [])
            prev_id = None
            for i, step in enumerate(steps):
                step_id = f"attack_step:{chain.get('name', '')}:{i}"
                self.add_node(GraphNode(
                    id=step_id, node_type="attack_step", label=step,
                    severity=chain.get("impact", "medium"),
                    properties={"chain_name": chain.get("name", "")},
                ))
                if prev_id:
                    self.add_edge(GraphEdge(
                        source_id=prev_id, target_id=step_id,
                        edge_type="leads_to", label="next step",
                        confidence=chain.get("confidence", 0.5),
                    ))
                prev_id = step_id
    
    def find_attack_paths(
        self,
        start_type: str = "asset",
        end_type: str = "vuln",
        max_depth: int = 10,
    ) -> List[List[str]]:
        """Find all attack paths from nodes of start_type to nodes of end_type."""
        start_nodes = [
            nid for nid, n in self._nodes.items() if n.node_type == start_type
        ]
        end_nodes = set(
            nid for nid, n in self._nodes.items() if n.node_type == end_type
        )
        
        paths = []
        for start in start_nodes:
            self._dfs(start, end_nodes, [], set(), paths, max_depth)
        
        return paths
    
    def _dfs(
        self,
        current: str,
        targets: Set[str],
        path: List[str],
        visited: Set[str],
        results: List[List[str]],
        max_depth: int,
    ):
        if len(path) > max_depth:
            return
        
        path.append(current)
        visited.add(current)
        
        if current in targets and len(path) > 1:
            results.append(list(path))
        
        for neighbor in self._adjacency.get(current, []):
            if neighbor not in visited:
                self._dfs(neighbor, targets, path, visited, results, max_depth)
        
        path.pop()
        visited.discard(current)
    
    def get_critical_paths(self) -> List[Dict[str, Any]]:
        """Get the most critical attack paths (to critical/high vulns)."""
        critical_vulns = set(
            nid for nid, n in self._nodes.items()
            if n.node_type == "vuln" and n.severity in ("critical", "high")
        )
        
        assets = [
            nid for nid, n in self._nodes.items() if n.node_type == "asset"
        ]
        
        paths = []
        for asset in assets:
            self._dfs(asset, critical_vulns, [], set(), paths, 10)
        
        return [
            {
                "path": [self._nodes[nid].label for nid in p],
                "length": len(p),
                "end_severity": self._nodes[p[-1]].severity if p else "unknown",
            }
            for p in paths
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize the graph for storage/reporting."""
        return {
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges],
            "stats": {
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "node_types": self._count_by("node_type"),
            },
        }
    
    def _count_by(self, field: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self._nodes.values():
            val = getattr(node, field, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts
    
    def summary(self) -> str:
        """Human-readable graph summary."""
        stats = self._count_by("node_type")
        lines = [f"Attack Graph: {len(self._nodes)} nodes, {len(self._edges)} edges"]
        for ntype, count in sorted(stats.items()):
            lines.append(f"  {ntype}: {count}")
        
        critical_paths = self.get_critical_paths()
        if critical_paths:
            lines.append(f"  Critical paths: {len(critical_paths)}")
            for cp in critical_paths[:3]:
                lines.append(f"    → {' → '.join(cp['path'][:6])}")
        
        return "\n".join(lines)
