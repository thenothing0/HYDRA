"""
╔══════════════════════════════════════════════════════════════╗
║  Validation Agent — False Positive Filtering & Scoring      ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import MemoryBus, Task

logger = logging.getLogger("hydra.agent.validation")


class ValidationAgent(BaseAgent):
    AGENT_TYPE = "validation"
    AGENT_NAME = "Validation Agent"
    
    def __init__(self, bus: MemoryBus, ai_router=None, learning_engine=None):
        super().__init__(bus)
        self.ai = ai_router
        self.learning = learning_engine
    
    async def execute(self, task: Task) -> Dict[str, Any]:
        handlers = {
            "false_positive_filter": self._filter_false_positives,
            "confidence_scoring": self._score_confidence,
        }
        handler = handlers.get(task.task_type)
        if not handler:
            raise ValueError(f"Unknown task type: {task.task_type}")
        return await handler(task)
    
    async def _filter_false_positives(self, task: Task) -> Dict[str, Any]:
        """Filter false positives using heuristics and AI."""
        context = task.payload.get("context", {})
        
        all_findings = []
        for phase_results in context.values():
            if isinstance(phase_results, list):
                for r in phase_results:
                    if isinstance(r, dict):
                        all_findings.extend(r.get("findings", []))
        
        validated = []
        rejected = []
        
        for finding in all_findings:
            score = self._heuristic_score(finding)
            
            # Check learning engine for historical accuracy
            if self.learning:
                historical = await self.learning.get_historical_accuracy(
                    finding.get("template_id", finding.get("type", ""))
                )
                if historical is not None:
                    score = score * 0.6 + historical * 0.4
            
            finding["confidence_score"] = round(score, 3)
            
            if score >= 0.5:
                validated.append(finding)
            else:
                finding["rejection_reason"] = "Below confidence threshold"
                rejected.append(finding)
        
        self.logger.info(
            f"Validated: {len(validated)}, Rejected: {len(rejected)} findings"
        )
        return {
            "task_type": "false_positive_filter",
            "target": task.payload["target"],
            "validated_findings": validated,
            "rejected_findings": rejected,
            "validation_rate": len(validated) / max(len(all_findings), 1),
        }
    
    def _heuristic_score(self, finding: Dict[str, Any]) -> float:
        """Score a finding using heuristic rules."""
        score = 0.5  # base score
        
        severity = str(finding.get("severity", "")).lower()
        severity_boost = {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.0}
        score += severity_boost.get(severity, 0.0)
        
        # Penalize info-only or generic findings
        name = str(finding.get("name", "")).lower()
        generic_indicators = ["detect", "version", "disclosure", "info"]
        if any(g in name for g in generic_indicators):
            score -= 0.15
        
        # Boost findings with evidence
        if finding.get("matched_at") or finding.get("evidence"):
            score += 0.1
        
        return max(0.0, min(1.0, score))
    
    async def _score_confidence(self, task: Task) -> Dict[str, Any]:
        """Assign final confidence scores using AI analysis."""
        context = task.payload.get("context", {})
        
        validated = []
        for r in context.get("validation", context.get("hypothesis", [])):
            if isinstance(r, dict):
                validated.extend(r.get("validated_findings", r.get("findings", [])))
        
        scored_findings = []
        for finding in validated:
            existing_score = finding.get("confidence_score", 0.5)
            
            # AI-enhanced scoring
            if self.ai:
                try:
                    prompt = (
                        f"Rate the likelihood this is a true positive (0.0-1.0):\n"
                        f"Finding: {finding.get('name', 'Unknown')}\n"
                        f"Severity: {finding.get('severity', 'unknown')}\n"
                        f"Type: {finding.get('type', 'unknown')}\n"
                        f"Matched at: {finding.get('matched_at', 'N/A')}\n"
                        "Return ONLY a decimal number."
                    )
                    ai_score = await self.ai.query(prompt, task_type="scoring")
                    if ai_score:
                        try:
                            ai_val = float(ai_score.strip())
                            finding["confidence_score"] = round(
                                existing_score * 0.4 + ai_val * 0.6, 3
                            )
                            finding["ai_scored"] = True
                        except ValueError:
                            pass
                except Exception:
                    pass
            
            scored_findings.append(finding)
        
        # Sort by confidence
        scored_findings.sort(key=lambda f: f.get("confidence_score", 0), reverse=True)
        
        return {
            "task_type": "confidence_scoring",
            "target": task.payload["target"],
            "scored_findings": scored_findings,
            "count": len(scored_findings),
        }
