"""
╔══════════════════════════════════════════════════════════════╗
║  AI Safety — Hallucination Defense & Evidence Validation    ║
║  No finding without evidence, reproduction, validation     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.ai.safety")


class HallucinationDefense:
    """
    Prevents hallucinated findings from being reported.
    
    Rules:
      - No finding without evidence
      - No finding without reproduction path
      - No finding without validation score
      - Unsupported claims are flagged
      - Tool output must be present
    """

    # Phrases that indicate AI hallucination
    HALLUCINATION_INDICATORS = [
        "i believe", "it's possible that", "theoretically",
        "might be vulnerable", "could potentially",
        "i think", "it seems like", "probably",
        "in my experience", "typically",
        "based on my knowledge", "as an ai",
    ]

    # Required fields for a valid finding
    REQUIRED_FIELDS = ["name", "severity", "evidence"]

    def validate_finding(
        self, finding: Dict[str, Any],
        tool_output: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a finding against hallucination criteria.
        
        Returns validation result with hallucination score.
        """
        issues = []
        score = 0.0  # 0.0 = definitely real, 1.0 = definitely hallucinated

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if not finding.get(field):
                issues.append(f"Missing required field: {field}")
                score += 0.2

        # Check for evidence
        evidence = finding.get("evidence", "")
        if not evidence and not finding.get("matched_at"):
            issues.append("No evidence or match location provided")
            score += 0.3

        # Check for reproduction steps
        if not finding.get("reproduction_steps"):
            issues.append("No reproduction steps")
            score += 0.1

        # Check tool output backing
        if tool_output is None:
            issues.append("No tool output to verify against")
            score += 0.15

        # Check for hallucination language in description
        desc = str(finding.get("description", "")).lower()
        name = str(finding.get("name", "")).lower()
        combined = desc + " " + name

        hal_count = sum(
            1 for ind in self.HALLUCINATION_INDICATORS
            if ind in combined
        )
        if hal_count > 0:
            score += min(hal_count * 0.1, 0.3)
            issues.append(
                f"Hallucination language detected ({hal_count} indicators)"
            )

        # Check severity claim vs evidence
        severity = str(finding.get("severity", "")).lower()
        if severity in ("critical", "high") and not evidence:
            issues.append(
                f"High severity ({severity}) claimed without evidence"
            )
            score += 0.2

        # Validate confidence score exists
        if "confidence_score" not in finding:
            issues.append("No confidence score")
            score += 0.05

        score = min(score, 1.0)

        return {
            "is_valid": score < 0.5,
            "hallucination_score": round(score, 4),
            "issues": issues,
            "risk_level": (
                "high" if score >= 0.7
                else "medium" if score >= 0.4
                else "low"
            ),
        }

    def validate_batch(
        self, findings: List[Dict[str, Any]],
        tool_outputs: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Validate multiple findings."""
        tool_outputs = tool_outputs or {}
        results = []
        valid_count = 0
        rejected_count = 0

        for finding in findings:
            fid = finding.get("template_id", str(hash(str(finding)))[:8])
            tool_out = tool_outputs.get(fid)
            result = self.validate_finding(finding, tool_out)

            if result["is_valid"]:
                valid_count += 1
            else:
                rejected_count += 1

            results.append({
                "finding_id": fid,
                "finding_name": finding.get("name", "Unknown"),
                **result,
            })

        return {
            "total": len(findings),
            "valid": valid_count,
            "rejected": rejected_count,
            "results": results,
        }

    def sanitize_ai_output(self, ai_text: str) -> str:
        """Remove hallucination language from AI output."""
        result = ai_text
        for indicator in self.HALLUCINATION_INDICATORS:
            pattern = re.compile(re.escape(indicator), re.IGNORECASE)
            result = pattern.sub("", result)
        # Clean up double spaces
        result = re.sub(r'\s+', ' ', result).strip()
        return result

    def evidence_check(self, finding: Dict[str, Any]) -> bool:
        """
        Strict evidence check.
        
        A finding CANNOT be reported without:
          - Evidence
          - Reproduction path
          - Validation score
        """
        has_evidence = bool(
            finding.get("evidence")
            or finding.get("matched_at")
            or finding.get("proof_of_impact")
        )
        has_reproduction = bool(
            finding.get("reproduction_steps")
            or finding.get("matched_at")
        )
        has_score = "confidence_score" in finding

        return has_evidence and has_reproduction and has_score
