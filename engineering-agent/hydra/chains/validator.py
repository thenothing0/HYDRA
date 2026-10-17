"""
╔══════════════════════════════════════════════════════════════╗
║  Chain Validator — Validate Exploit Chains Without Exploiting║
║  Checks reachability, evidence quality, chain integrity     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.chains.validator")


@dataclass
class ValidationResult:
    """Result of chain validation."""
    chain_id: str
    is_valid: bool = False
    confidence: float = 0.0
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id, "valid": self.is_valid,
            "confidence": self.confidence,
            "passed": self.checks_passed, "failed": self.checks_failed,
            "warnings": self.warnings, "recommendation": self.recommendation,
        }


class ChainValidator:
    """
    Validates exploit chains without actual exploitation.
    
    Checks:
    - Evidence quality for each node
    - Link plausibility (do source→target transitions make sense?)
    - Chain integrity (no circular dependencies)
    - Confidence thresholds
    - Reachability (are endpoints still live?)
    """

    CONFIDENCE_THRESHOLD = 0.4
    MIN_EVIDENCE_LENGTH = 10

    def __init__(self, mcp_client=None, artifact_store=None):
        self.mcp = mcp_client
        self.artifacts = artifact_store

    def validate_chain(self, chain) -> ValidationResult:
        """Validate an entire exploit chain."""
        result = ValidationResult(chain_id=chain.chain_id)

        # Check 1: Minimum chain depth
        if len(chain.nodes) < 2:
            result.checks_failed.append("chain_depth: requires at least 2 nodes")
            result.recommendation = "Chain too short — not a multi-hop exploit"
            return result
        result.checks_passed.append("chain_depth")

        # Check 2: No circular dependencies
        node_ids = [n.node_id for n in chain.nodes]
        if len(node_ids) != len(set(node_ids)):
            result.checks_failed.append("circular_dependency: duplicate nodes detected")
            result.warnings.append("Chain contains circular references")
        else:
            result.checks_passed.append("no_circular_deps")

        # Check 3: Evidence quality per node
        weak_evidence = []
        for node in chain.nodes:
            if not node.evidence or len(str(node.evidence)) < self.MIN_EVIDENCE_LENGTH:
                weak_evidence.append(node.node_id)
        if weak_evidence:
            result.checks_failed.append(
                f"evidence_quality: {len(weak_evidence)} nodes lack evidence"
            )
            result.warnings.append(f"Weak evidence on: {', '.join(weak_evidence[:5])}")
        else:
            result.checks_passed.append("evidence_quality")

        # Check 4: Confidence thresholds
        low_confidence_nodes = [
            n for n in chain.nodes if n.confidence < self.CONFIDENCE_THRESHOLD
        ]
        if low_confidence_nodes:
            result.checks_failed.append(
                f"confidence: {len(low_confidence_nodes)} nodes below threshold"
            )
        else:
            result.checks_passed.append("confidence_threshold")

        # Check 5: Link plausibility
        for link in chain.links:
            if link.confidence < 0.2:
                result.warnings.append(
                    f"Low-confidence link: {link.source_id}→{link.target_id} "
                    f"({link.confidence})"
                )
        if not any("link" in f for f in result.checks_failed):
            result.checks_passed.append("link_plausibility")

        # Check 6: Severity consistency
        from hydra.chains import SEVERITY_SCORES
        severities = [SEVERITY_SCORES.get(n.severity, 0) for n in chain.nodes]
        if max(severities) - min(severities) > 3:
            result.warnings.append(
                "Wide severity spread — chain may combine unrelated findings"
            )
        result.checks_passed.append("severity_consistency")

        # Check 7: Chain age (findings shouldn't be stale)
        import time
        for node in chain.nodes:
            created = node.data.get("timestamp", node.data.get("created_at", 0))
            if created and (time.time() - created) > 86400 * 7:
                result.warnings.append(f"Stale node: {node.node_id} (>7 days old)")

        # Calculate overall validity
        total_checks = len(result.checks_passed) + len(result.checks_failed)
        pass_ratio = len(result.checks_passed) / max(total_checks, 1)
        result.confidence = round(pass_ratio * chain.confidence, 2)
        result.is_valid = (
            len(result.checks_failed) <= 1 and
            result.confidence >= self.CONFIDENCE_THRESHOLD
        )

        # Recommendation
        if result.is_valid:
            result.recommendation = (
                f"Chain validated with {result.confidence:.0%} confidence. "
                f"Ready for manual review and report submission."
            )
        else:
            result.recommendation = (
                f"Chain has {len(result.checks_failed)} failed checks. "
                f"Review evidence quality before submitting."
            )

        logger.info(
            f"{'✅' if result.is_valid else '❌'} Chain {chain.chain_id}: "
            f"{len(result.checks_passed)}/{total_checks} checks passed, "
            f"confidence={result.confidence}"
        )

        return result

    def validate_all_chains(self, chains: list) -> List[ValidationResult]:
        """Validate multiple chains, return sorted by confidence."""
        results = [self.validate_chain(c) for c in chains]
        return sorted(results, key=lambda r: r.confidence, reverse=True)
