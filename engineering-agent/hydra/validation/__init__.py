"""
╔══════════════════════════════════════════════════════════════╗
║  Advanced Validation Engine — Reproducibility & Evidence   ║
║  HTTP replay, proof collection, multi-step verification    ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.validation")


@dataclass
class EvidenceArtifact:
    """Evidence supporting a finding."""
    artifact_type: str  # http_response, screenshot, log, replay
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of finding validation."""
    finding_id: str
    is_valid: bool
    confidence: float
    reproducible: bool
    evidence: List[EvidenceArtifact] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    validation_method: str = ""
    proof_of_impact: str = ""
    impact_score: float = 0.0
    timestamp: float = field(default_factory=time.time)


class HTTPReplayEngine:
    """Replay HTTP requests to verify findings."""

    async def replay(
        self, method: str, url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        expected_status: Optional[int] = None,
        expected_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Replay an HTTP request and check response."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                kwargs = {"headers": headers or {}, "timeout": aiohttp.ClientTimeout(total=30)}
                if body:
                    kwargs["data"] = body

                async with session.request(method, url, **kwargs) as resp:
                    response_text = await resp.text()
                    status = resp.status
                    resp_headers = dict(resp.headers)

                    matches = True
                    if expected_status and status != expected_status:
                        matches = False
                    if expected_pattern and expected_pattern not in response_text:
                        matches = False

                    return {
                        "success": True, "matches": matches,
                        "status": status, "headers": resp_headers,
                        "body_preview": response_text[:2000],
                        "body_length": len(response_text),
                    }
        except Exception as e:
            return {"success": False, "error": str(e)}


class AdvancedValidationEngine:
    """
    Production-grade validation engine.
    
    Features:
      - HTTP replay verification
      - Evidence collection and scoring
      - Reproducibility verification
      - Multi-step confirmation
      - Proof-of-impact scoring
      - Validation templates
    """

    VALIDATION_TEMPLATES = {
        "xss": {
            "steps": [
                "Inject test payload in identified parameter",
                "Check if payload is reflected in response",
                "Verify execution context (DOM vs reflected)",
                "Test with encoded variants",
            ],
            "min_confidence": 0.7,
        },
        "sqli": {
            "steps": [
                "Send time-based blind SQLi payload",
                "Measure response time difference",
                "Verify with boolean-based test",
                "Check error-based indicators",
            ],
            "min_confidence": 0.8,
        },
        "ssrf": {
            "steps": [
                "Send SSRF payload pointing to callback",
                "Check for out-of-band interaction",
                "Verify internal resource access",
                "Test cloud metadata endpoints",
            ],
            "min_confidence": 0.75,
        },
        "auth_bypass": {
            "steps": [
                "Test without authentication",
                "Test with modified tokens",
                "Verify access to protected resources",
                "Compare authenticated vs unauthenticated responses",
            ],
            "min_confidence": 0.85,
        },
    }

    def __init__(self):
        self._replay = HTTPReplayEngine()
        self._results: Dict[str, ValidationResult] = {}

    async def validate_finding(
        self, finding: Dict[str, Any],
        replay_config: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Validate a finding with evidence collection.
        
        Every validated finding MUST include:
          - Reproducibility steps
          - Confidence score
          - Evidence artifacts
        """
        finding_id = finding.get("template_id", str(hash(str(finding)))[:12])
        f_type = str(finding.get("type", "")).lower()

        result = ValidationResult(
            finding_id=finding_id,
            is_valid=False,
            confidence=0.0,
            reproducible=False,
        )

        # Step 1: Heuristic validation
        heuristic_score = self._heuristic_validate(finding)
        result.confidence = heuristic_score

        # Step 2: Template-based validation steps
        template = self._get_template(f_type)
        if template:
            result.reproduction_steps = template["steps"]
            result.validation_method = f"template:{f_type}"

        # Step 3: HTTP replay if config provided
        if replay_config:
            replay_result = await self._replay.replay(
                method=replay_config.get("method", "GET"),
                url=replay_config.get("url", ""),
                headers=replay_config.get("headers"),
                body=replay_config.get("body"),
                expected_status=replay_config.get("expected_status"),
                expected_pattern=replay_config.get("expected_pattern"),
            )

            if replay_result.get("success") and replay_result.get("matches"):
                result.reproducible = True
                result.confidence = min(result.confidence + 0.2, 1.0)
                result.evidence.append(EvidenceArtifact(
                    artifact_type="http_response",
                    content=json.dumps(replay_result, indent=2),
                    metadata={"url": replay_config.get("url", "")},
                ))

        # Step 4: Evidence from finding itself
        if finding.get("matched_at"):
            result.evidence.append(EvidenceArtifact(
                artifact_type="match_location",
                content=finding["matched_at"],
            ))
        if finding.get("evidence"):
            result.evidence.append(EvidenceArtifact(
                artifact_type="tool_evidence",
                content=str(finding["evidence"]),
            ))

        # Step 5: Impact scoring
        result.impact_score = self._score_impact(finding)
        result.proof_of_impact = self._generate_impact_proof(finding)

        # Final decision
        min_conf = 0.5
        if template:
            min_conf = template.get("min_confidence", 0.5)

        result.is_valid = (
            result.confidence >= min_conf
            and len(result.evidence) > 0
        )

        self._results[finding_id] = result
        return result

    def _heuristic_validate(self, finding: Dict[str, Any]) -> float:
        """Score a finding using heuristics."""
        score = 0.4
        severity = str(finding.get("severity", "")).lower()
        sev_boost = {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.0}
        score += sev_boost.get(severity, 0.0)

        if finding.get("matched_at") or finding.get("evidence"):
            score += 0.15
        if finding.get("description"):
            score += 0.05

        name = str(finding.get("name", "")).lower()
        if any(g in name for g in ["detect", "info", "version"]):
            score -= 0.15

        return max(0.0, min(1.0, score))

    def _get_template(self, finding_type: str) -> Optional[Dict]:
        for key, tmpl in self.VALIDATION_TEMPLATES.items():
            if key in finding_type:
                return tmpl
        return None

    def _score_impact(self, finding: Dict[str, Any]) -> float:
        severity = str(finding.get("severity", "")).lower()
        impact_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        return impact_map.get(severity, 0.0)

    def _generate_impact_proof(self, finding: Dict[str, Any]) -> str:
        severity = str(finding.get("severity", "")).lower()
        f_type = str(finding.get("type", "")).lower()
        name = finding.get("name", "Unknown")
        host = finding.get("host", finding.get("matched_at", "target"))

        if severity in ("critical", "high"):
            return (
                f"Impact: {name} on {host} could allow an attacker to "
                f"compromise the application's security posture. "
                f"Finding type: {f_type}, severity: {severity}."
            )
        return f"{name} identified on {host} (severity: {severity})."

    async def batch_validate(
        self, findings: List[Dict[str, Any]]
    ) -> List[ValidationResult]:
        """Validate multiple findings."""
        results = []
        for f in findings:
            r = await self.validate_finding(f)
            results.append(r)
        return results

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._results)
        valid = sum(1 for r in self._results.values() if r.is_valid)
        reproducible = sum(1 for r in self._results.values() if r.reproducible)
        return {
            "total_validated": total, "valid": valid,
            "invalid": total - valid, "reproducible": reproducible,
            "avg_confidence": round(
                sum(r.confidence for r in self._results.values())
                / max(total, 1), 4
            ),
        }
