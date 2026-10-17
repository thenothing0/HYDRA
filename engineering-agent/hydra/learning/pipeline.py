"""
Learning Pipeline — closes the loop between scanning and the ML models.

Responsibilities:
  1. Record every finding of a scan into the LearningEngine (raw, unlabeled).
  2. Auto-label findings using the AdvancedValidationEngine's verdict as a
     weak/preliminary signal (semi-supervised).
  3. Allow a human to override any label later (manual feedback).

Auto-labels are marked as such so a manual correction always wins.
"""

import logging
from typing import Any, Dict, List, Optional

from hydra.learning.engine import LearningEngine

logger = logging.getLogger("hydra.learning.pipeline")


class LearningPipeline:
    """Feeds scan results into the learning DB and derives training labels."""

    def __init__(self, learning_engine: Optional[LearningEngine] = None):
        self.learning = learning_engine or LearningEngine()
        self.learning.initialize()

    # ── Recording ──────────────────────────────
    def record_scan(self, scan_id: str, target: str,
                    findings: List[Dict[str, Any]],
                    tool_used: str = "") -> int:
        """Record all findings of a scan. Returns the number recorded."""
        for f in findings:
            self.learning.record_finding(
                scan_id=scan_id,
                target=target,
                finding_type=str(f.get("type") or f.get("name") or "unknown"),
                template_id=f.get("template_id", "") or self._synthetic_id(f),
                severity=str(f.get("severity", "info")),
                confidence=float(f.get("confidence", f.get("confidence_score", 0.5)) or 0.5),
                tool_used=tool_used or str(f.get("tool_used", f.get("tool", ""))),
            )
        logger.info(f"📥 Recorded {len(findings)} finding(s) for scan {scan_id}")
        return len(findings)

    @staticmethod
    def _synthetic_id(f: Dict[str, Any]) -> str:
        """Stable id for findings that lack a template_id (e.g. code_review)."""
        import hashlib
        key = f"{f.get('name','')}|{f.get('matched_at','')}|{f.get('severity','')}"
        return "cr-" + hashlib.sha1(key.encode()).hexdigest()[:12]

    # ── Auto-labeling (semi-supervised) ────────
    async def auto_label(self, scan_id: str,
                         findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Label findings using the validation engine's verdict.

        A finding validated as `is_valid=True` with confidence over the
        template threshold is labeled a true positive; otherwise false.
        Returns {"true_positive": n, "false_positive": m}.
        """
        from hydra.validation import AdvancedValidationEngine

        validator = AdvancedValidationEngine()
        tp = fp = 0
        for f in findings:
            template_id = f.get("template_id", "") or self._synthetic_id(f)
            result = await validator.validate_finding(f)
            is_tp = bool(result.is_valid)
            self.learning.mark_true_positive(scan_id, template_id, is_tp)
            f["auto_label"] = "tp" if is_tp else "fp"
            f["validation_confidence"] = round(result.confidence, 4)
            tp += int(is_tp)
            fp += int(not is_tp)
        logger.info(f"🏷️  Auto-labeled scan {scan_id}: {tp} TP / {fp} FP")
        return {"true_positive": tp, "false_positive": fp}

    # ── Manual override ────────────────────────
    def label(self, scan_id: str, template_id: str, is_true_positive: bool):
        """Human override — flips the stored label for a finding."""
        self.learning.mark_true_positive(scan_id, template_id, is_true_positive)
        logger.info(f"✍️  Manual label: {scan_id}/{template_id} = "
                    f"{'TP' if is_true_positive else 'FP'}")

    # ── Training ───────────────────────────────
    def labelled_count(self) -> int:
        return len(self.learning.export_labelled_findings())

    def train(self) -> Dict[str, Any]:
        """Train the FP classifier on all accumulated labelled data."""
        return self.learning.train_fp_classifier()
