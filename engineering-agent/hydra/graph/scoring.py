"""
╔══════════════════════════════════════════════════════════════╗
║  Attack Graph Scoring Engine — Risk Propagation & Analysis  ║
║  Blast radius estimation, privilege escalation detection,   ║
║  attack path prioritization, and graph-based scoring        ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.graph.scoring")


@dataclass
class PathScore:
    """Scored attack path."""
    path: List[str]
    path_labels: List[str]
    total_score: float
    blast_radius: float
    exploitability: float
    impact: float
    confidence: float
    privilege_escalation: bool
    chain_length: int
    risk_level: str  # critical, high, medium, low


@dataclass
class BlastRadiusResult:
    """Blast radius estimation for a compromised node."""
    source_node: str
    affected_nodes: List[str]
    affected_count: int
    max_depth_reached: int
    severity_distribution: Dict[str, int]
    estimated_impact: float
    critical_assets_affected: List[str]


class GraphScoringEngine:
    """
    Graph-based risk scoring engine.
    
    Features:
      - Risk propagation along attack paths
      - Blast radius estimation
      - Privilege escalation chain detection
      - Attack path prioritization
      - CVSS-compatible severity scoring
    """

    SEVERITY_WEIGHTS = {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.5,
    }

    NODE_TYPE_VALUE = {
        "credential": 9.0,
        "vuln": 7.0,
        "service": 5.0,
        "endpoint": 3.0,
        "asset": 6.0,
        "attack_step": 4.0,
    }

    PRIV_ESC_INDICATORS = [
        "privilege", "escalation", "admin", "root", "sudo",
        "credential", "auth", "session", "takeover", "rce",
        "command_injection", "code_execution", "shell",
    ]

    def __init__(self, attack_graph):
        """
        Args:
            attack_graph: AttackGraph instance to score.
        """
        self.graph = attack_graph

    def score_all_paths(self, max_depth: int = 10) -> List[PathScore]:
        """Score all attack paths in the graph and return sorted by risk."""
        paths = self.graph.find_attack_paths(
            start_type="asset", end_type="vuln", max_depth=max_depth
        )

        scored = []
        for path in paths:
            score = self._score_path(path)
            if score:
                scored.append(score)

        scored.sort(key=lambda s: s.total_score, reverse=True)
        return scored

    def _score_path(self, path: List[str]) -> Optional[PathScore]:
        """Score a single attack path."""
        if len(path) < 2:
            return None

        nodes = self.graph._nodes
        edges = self.graph._edges

        # Calculate exploitability (how easy to traverse the path)
        edge_confidences = []
        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            for edge in edges:
                if edge.source_id == src and edge.target_id == tgt:
                    edge_confidences.append(edge.confidence)
                    break
            else:
                edge_confidences.append(0.3)

        exploitability = (
            math.prod(edge_confidences) ** (1 / len(edge_confidences))
            if edge_confidences else 0.0
        )

        # Calculate impact based on end node severity
        end_node = nodes.get(path[-1])
        impact = self.SEVERITY_WEIGHTS.get(
            end_node.severity if end_node else "info", 0.5
        )

        # Detect privilege escalation
        priv_esc = self._detect_privilege_escalation(path)

        # Path length penalty (shorter = more dangerous)
        length_factor = 1.0 / (1.0 + (len(path) - 2) * 0.15)

        # Node type value accumulation
        node_values = []
        for nid in path:
            node = nodes.get(nid)
            if node:
                node_values.append(
                    self.NODE_TYPE_VALUE.get(node.node_type, 1.0)
                )

        avg_node_value = sum(node_values) / len(node_values) if node_values else 1.0

        # Total score
        total = (
            exploitability * 0.30
            + (impact / 10.0) * 0.35
            + length_factor * 0.15
            + (avg_node_value / 10.0) * 0.10
            + (0.10 if priv_esc else 0.0)
        )

        # Blast radius for end node
        blast = self.estimate_blast_radius(path[-1], max_depth=5)
        blast_score = min(blast.estimated_impact / 10.0, 1.0)

        total = total * 0.85 + blast_score * 0.15

        # Risk level
        if total >= 0.8:
            risk = "critical"
        elif total >= 0.6:
            risk = "high"
        elif total >= 0.4:
            risk = "medium"
        else:
            risk = "low"

        path_labels = []
        for nid in path:
            node = nodes.get(nid)
            path_labels.append(node.label if node else nid)

        return PathScore(
            path=path,
            path_labels=path_labels,
            total_score=round(total, 4),
            blast_radius=blast.estimated_impact,
            exploitability=round(exploitability, 4),
            impact=impact,
            confidence=round(
                sum(edge_confidences) / len(edge_confidences)
                if edge_confidences else 0.0, 4
            ),
            privilege_escalation=priv_esc,
            chain_length=len(path),
            risk_level=risk,
        )

    def _detect_privilege_escalation(self, path: List[str]) -> bool:
        """Detect if a path represents a privilege escalation chain."""
        nodes = self.graph._nodes
        for nid in path:
            node = nodes.get(nid)
            if not node:
                continue
            label_lower = node.label.lower()
            props_str = str(node.properties).lower()
            combined = label_lower + " " + props_str
            if any(ind in combined for ind in self.PRIV_ESC_INDICATORS):
                return True
        return False

    def estimate_blast_radius(
        self, node_id: str, max_depth: int = 5
    ) -> BlastRadiusResult:
        """
        Estimate the blast radius if a given node is compromised.
        
        Walks outward from the node and calculates how many other
        nodes/assets would be affected.
        """
        nodes = self.graph._nodes
        adjacency = self.graph._adjacency

        if node_id not in nodes:
            return BlastRadiusResult(
                source_node=node_id, affected_nodes=[], affected_count=0,
                max_depth_reached=0, severity_distribution={},
                estimated_impact=0.0, critical_assets_affected=[],
            )

        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(node_id, 0)]
        affected: List[str] = []
        max_depth_reached = 0
        sev_dist: Dict[str, int] = {}
        critical_assets: List[str] = []

        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            if current != node_id:
                affected.append(current)
                max_depth_reached = max(max_depth_reached, depth)
                node = nodes.get(current)
                if node:
                    sev = node.severity
                    sev_dist[sev] = sev_dist.get(sev, 0) + 1
                    if sev in ("critical", "high") or node.node_type == "credential":
                        critical_assets.append(current)

            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        # Estimated impact score
        impact = 0.0
        for nid in affected:
            node = nodes.get(nid)
            if node:
                impact += self.SEVERITY_WEIGHTS.get(node.severity, 0.5)
                impact += self.NODE_TYPE_VALUE.get(node.node_type, 1.0) * 0.3

        impact = min(impact, 100.0)

        return BlastRadiusResult(
            source_node=node_id,
            affected_nodes=affected,
            affected_count=len(affected),
            max_depth_reached=max_depth_reached,
            severity_distribution=sev_dist,
            estimated_impact=round(impact, 2),
            critical_assets_affected=critical_assets,
        )

    def get_risk_propagation_scores(self) -> Dict[str, float]:
        """
        Compute risk scores for every node using reverse propagation.
        
        Nodes reachable from high-severity vulnerabilities inherit
        partial risk scores, decaying with distance.
        """
        nodes = self.graph._nodes
        reverse_adj = self.graph._reverse_adj

        scores: Dict[str, float] = {}

        # Initialize vulnerability nodes with their severity weight
        for nid, node in nodes.items():
            if node.node_type == "vuln":
                scores[nid] = self.SEVERITY_WEIGHTS.get(node.severity, 0.5)
            else:
                scores[nid] = 0.0

        # Propagate backwards (BFS from vulns)
        DECAY = 0.6
        MAX_PROPAGATION_DEPTH = 8

        vuln_nodes = [nid for nid, n in nodes.items() if n.node_type == "vuln"]
        for vuln_id in vuln_nodes:
            vuln_score = scores[vuln_id]
            visited: Set[str] = {vuln_id}
            queue: List[Tuple[str, int]] = [(vuln_id, 0)]

            while queue:
                current, depth = queue.pop(0)
                if depth >= MAX_PROPAGATION_DEPTH:
                    continue
                propagated = vuln_score * (DECAY ** (depth + 1))

                for parent in reverse_adj.get(current, []):
                    if parent not in visited:
                        visited.add(parent)
                        scores[parent] = max(scores[parent], propagated)
                        queue.append((parent, depth + 1))

        return {nid: round(s, 4) for nid, s in scores.items() if s > 0}

    def find_privilege_escalation_chains(self) -> List[PathScore]:
        """Find all paths that represent privilege escalation opportunities."""
        all_paths = self.score_all_paths()
        return [p for p in all_paths if p.privilege_escalation]

    def get_prioritized_targets(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """
        Get a prioritized list of targets for further investigation.
        
        Combines risk scores, blast radius, and path analysis.
        """
        risk_scores = self.get_risk_propagation_scores()
        nodes = self.graph._nodes

        targets = []
        for nid, score in sorted(risk_scores.items(), key=lambda x: x[1], reverse=True):
            node = nodes.get(nid)
            if not node:
                continue
            blast = self.estimate_blast_radius(nid, max_depth=3)
            targets.append({
                "node_id": nid,
                "label": node.label,
                "node_type": node.node_type,
                "severity": node.severity,
                "risk_score": score,
                "blast_radius": blast.affected_count,
                "blast_impact": blast.estimated_impact,
                "critical_downstream": len(blast.critical_assets_affected),
            })
            if len(targets) >= top_n:
                break

        return targets

    def generate_scoring_report(self) -> Dict[str, Any]:
        """Generate a comprehensive scoring report for the attack graph."""
        scored_paths = self.score_all_paths()
        risk_scores = self.get_risk_propagation_scores()
        priv_esc_chains = self.find_privilege_escalation_chains()
        priority_targets = self.get_prioritized_targets()

        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for path in scored_paths:
            risk_distribution[path.risk_level] = (
                risk_distribution.get(path.risk_level, 0) + 1
            )

        return {
            "summary": {
                "total_paths_analyzed": len(scored_paths),
                "critical_paths": risk_distribution["critical"],
                "high_risk_paths": risk_distribution["high"],
                "privilege_escalation_chains": len(priv_esc_chains),
                "nodes_with_risk": len(risk_scores),
                "priority_targets": len(priority_targets),
            },
            "top_attack_paths": [
                {
                    "path": p.path_labels,
                    "score": p.total_score,
                    "risk": p.risk_level,
                    "exploitability": p.exploitability,
                    "impact": p.impact,
                    "priv_esc": p.privilege_escalation,
                    "blast_radius": p.blast_radius,
                }
                for p in scored_paths[:10]
            ],
            "privilege_escalation_chains": [
                {
                    "path": p.path_labels,
                    "score": p.total_score,
                    "confidence": p.confidence,
                }
                for p in priv_esc_chains[:5]
            ],
            "priority_targets": priority_targets[:10],
            "risk_distribution": risk_distribution,
        }
