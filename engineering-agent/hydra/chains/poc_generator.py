"""
╔══════════════════════════════════════════════════════════════╗
║  PoC Generator — Safe Proof-of-Concept Construction         ║
║  Produces reproducible HTTP sequences without exploitation  ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.chains.poc")


@dataclass
class PoCStep:
    """Single step in a PoC reproduction."""
    step_number: int
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    description: str = ""
    expected_status: int = 200
    expected_pattern: str = ""
    extract_from_response: str = ""  # regex or jq-like path
    notes: str = ""

    def to_dict(self) -> Dict:
        return {
            "step": self.step_number, "method": self.method,
            "url": self.url, "headers": self.headers,
            "body": self.body if self.body else None,
            "description": self.description,
            "expected_status": self.expected_status,
            "expected_pattern": self.expected_pattern or None,
            "extract": self.extract_from_response or None,
            "notes": self.notes or None,
        }


@dataclass
class ProofOfConcept:
    """Complete PoC with metadata and reproduction steps."""
    poc_id: str
    title: str
    chain_id: str = ""
    severity: str = "info"
    description: str = ""
    impact: str = ""
    steps: List[PoCStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    cleanup_steps: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "poc_id": self.poc_id, "title": self.title,
            "chain_id": self.chain_id, "severity": self.severity,
            "description": self.description, "impact": self.impact,
            "prerequisites": self.prerequisites,
            "steps": [s.to_dict() for s in self.steps],
            "cleanup": self.cleanup_steps,
            "environment": self.environment,
        }

    def to_curl(self) -> str:
        """Export PoC steps as curl commands."""
        lines = [f"# PoC: {self.title}", f"# Severity: {self.severity}", ""]
        for step in self.steps:
            parts = [f"curl -s -X {step.method}"]
            for k, v in step.headers.items():
                parts.append(f'  -H "{k}: {v}"')
            if step.body:
                parts.append(f"  -d '{step.body}'")
            parts.append(f'  "{step.url}"')
            lines.append(f"# Step {step.step_number}: {step.description}")
            lines.append(" \\\n".join(parts))
            lines.append("")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Export PoC as markdown report."""
        lines = [
            f"# {self.title}",
            f"**Severity**: {self.severity.upper()}",
            f"**Chain ID**: {self.chain_id}",
            "", f"## Description", self.description,
            "", f"## Impact", self.impact,
        ]
        if self.prerequisites:
            lines.extend(["", "## Prerequisites"])
            for p in self.prerequisites:
                lines.append(f"- {p}")
        lines.extend(["", "## Reproduction Steps"])
        for step in self.steps:
            lines.append(f"\n### Step {step.step_number}: {step.description}")
            lines.append(f"```http\n{step.method} {step.url}")
            for k, v in step.headers.items():
                lines.append(f"{k}: {v}")
            if step.body:
                lines.append(f"\n{step.body}")
            lines.append("```")
            if step.notes:
                lines.append(f"> {step.notes}")
        return "\n".join(lines)


class PoCGenerator:
    """Generates safe, reproducible PoC scripts from exploit chains."""

    def __init__(self, artifact_store=None):
        self.artifacts = artifact_store

    def generate_from_chain(self, chain, target: str = "") -> ProofOfConcept:
        """Generate PoC from an ExploitChain object."""
        poc = ProofOfConcept(
            poc_id=f"poc-{chain.chain_id}",
            title=f"Exploit Chain: {' → '.join(n.label for n in chain.nodes)}",
            chain_id=chain.chain_id,
            severity=chain.overall_severity,
            description=f"Multi-hop exploit chain ({chain.depth} steps) against {target}",
            impact=f"Blast radius: {chain.blast_radius}, "
                   f"Exploitability: {chain.exploitability_score}",
        )

        for i, node in enumerate(chain.nodes):
            matched_at = node.data.get("matched_at", target)
            step = PoCStep(
                step_number=i + 1,
                method="GET",
                url=matched_at if matched_at.startswith("http") else f"https://{target}{matched_at}",
                description=f"Identify: {node.label}",
                expected_pattern=node.evidence[:100] if node.evidence else "",
                notes=f"Severity: {node.severity}, Confidence: {node.confidence}",
            )

            # Add reproduction command from finding data
            repro = node.data.get("reproduction_steps", "")
            if repro:
                step.notes += f"\nRepro: {repro}"

            poc.steps.append(step)

            # Add pivot step if there's a link
            if i < len(chain.links):
                link = chain.links[i]
                pivot = PoCStep(
                    step_number=i + 1,
                    method="GET",
                    url=matched_at,
                    description=f"Pivot: {link.technique} — {link.description}",
                    notes=f"Confidence: {link.confidence}",
                )
                # Don't duplicate — just add context to main step
                poc.steps[-1].notes += f"\n→ Next: {link.description}"

        poc.prerequisites = [
            "Authorized testing scope",
            "Valid session/credentials (if authenticated endpoints)",
        ]
        poc.cleanup_steps = [
            "Review any state changes made during testing",
            "Document all requests for report submission",
        ]

        # Save artifact
        if self.artifacts:
            self.artifacts.save_parsed_output(
                target, "evidence", f"poc_{chain.chain_id}",
                poc.to_dict()
            )

        return poc

    def generate_from_finding(self, finding: Dict,
                               target: str = "") -> ProofOfConcept:
        """Generate PoC from a single finding."""
        name = finding.get("name", "Unknown")
        matched_at = finding.get("matched_at", target)

        poc = ProofOfConcept(
            poc_id=f"poc-{finding.get('template_id', 'manual')}",
            title=name,
            severity=finding.get("severity", "info"),
            description=f"Vulnerability: {name}",
            impact=f"Severity: {finding.get('severity', 'info')}",
        )

        poc.steps.append(PoCStep(
            step_number=1,
            method="GET",
            url=matched_at if matched_at.startswith("http") else f"https://{target}",
            description=f"Access: {matched_at}",
            expected_pattern=str(finding.get("evidence", ""))[:200],
            notes=finding.get("reproduction_steps", ""),
        ))

        return poc
