"""Continuous red-team testing loop + coverage audit + stopping conditions.

Implements doctrine §1 (the DISCOVER→…→FINAL_REPORT loop), §16 (mandatory
coverage audit that gates the final report) and §17 (the only three legitimate
stopping conditions). A confirmed finding is an event inside the loop, never a
reason to stop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from hydra.engagement.checklist import Checklist, AreaStatus
from hydra.engagement.inventory import AttackSurfaceInventory


class Phase(str, Enum):
    DISCOVER = "discover"
    INVENTORY = "inventory"
    TEST = "test"
    ANALYZE = "analyze"
    EXPAND = "expand"
    TEST_RELATED = "test_related"
    CORRELATE = "correlate"
    COVERAGE_REVIEW = "coverage_review"
    RETEST = "retest"
    FINAL_REPORT = "final_report"


# Canonical loop order (doctrine §1). COVERAGE_REVIEW can route back to TEST.
PHASE_ORDER: List[Phase] = [
    Phase.DISCOVER, Phase.INVENTORY, Phase.TEST, Phase.ANALYZE, Phase.EXPAND,
    Phase.TEST_RELATED, Phase.CORRELATE, Phase.COVERAGE_REVIEW, Phase.RETEST,
    Phase.FINAL_REPORT,
]


class StopReason(str, Enum):
    SUFFICIENT_COVERAGE = "sufficient_coverage"   # §17-A
    EXPLICIT_LIMITATION = "explicit_limitation"   # §17-B
    SAFETY_BOUNDARY = "safety_boundary"           # §17-C


# The 16 coverage-audit questions (doctrine §16), each resolved from state.
@dataclass
class CoverageResult:
    ready: bool
    coverage_ratio: float
    unmet: List[str] = field(default_factory=list)
    checks: Dict[str, bool] = field(default_factory=dict)


class Engagement:
    """Drives one authorized engagement through the continuous loop.

    The object is intentionally decision-only: it tracks state and tells the
    caller what to do next (which phase, which untested items, whether a final
    report is permitted). Executing tools is the caller's job — that keeps the
    scope/safety enforcement in one place (HydraEngine)."""

    def __init__(self, target: str, scope_loaded: bool = False):
        self.target = target
        self.scope_loaded = scope_loaded
        self.checklist = Checklist()
        self.inventory = AttackSurfaceInventory()
        self.findings: List[Dict[str, Any]] = []
        self.attack_chains: List[Dict[str, Any]] = []
        self.phase: Phase = Phase.DISCOVER
        self.started_at = time.time()
        self.stopped: Optional[StopReason] = None
        self.stop_note: str = ""
        self._log: List[Dict[str, Any]] = []

    # ── Loop control ───────────────────────────
    def advance(self) -> Phase:
        """Move to the next loop phase (wrapping COVERAGE_REVIEW → TEST when
        coverage is insufficient). Returns the new phase."""
        if self.phase == Phase.COVERAGE_REVIEW:
            cov = self.coverage_audit()
            self.phase = Phase.RETEST if cov.ready else Phase.TEST
            self._record("advance", from_="coverage_review",
                         to=self.phase.value, ready=cov.ready)
            return self.phase
        idx = PHASE_ORDER.index(self.phase)
        self.phase = PHASE_ORDER[min(idx + 1, len(PHASE_ORDER) - 1)]
        self._record("advance", to=self.phase.value)
        return self.phase

    def record_finding(self, finding: Dict[str, Any]) -> None:
        """A confirmed finding — an event inside the loop, not a stop."""
        self.findings.append(finding)
        self._record("finding", name=finding.get("name", ""),
                     severity=finding.get("severity", "info"))

    # ── Stopping conditions (§17) ──────────────
    def stop(self, reason: StopReason, note: str = "") -> None:
        self.stopped = reason if isinstance(reason, StopReason) else StopReason(reason)
        self.stop_note = note
        self._record("stop", reason=self.stopped.value, note=note)

    def is_active(self) -> bool:
        return self.stopped is None

    # ── Coverage audit (§16) ───────────────────
    def coverage_audit(self) -> CoverageResult:
        """Resolve the 16 coverage questions from live state. Only when every
        applicable check passes (and no area is still pending) is a final
        report permitted."""
        inv = self.inventory
        cl = self.checklist

        def done(slug: str) -> bool:
            rec = cl.get(slug)
            return bool(rec and rec.status in
                        (AreaStatus.DONE, AreaStatus.NA, AreaStatus.BLOCKED))

        checks: Dict[str, bool] = {
            "assets_inventoried": inv.count() > 0,
            "endpoints_evaluated": done("endpoint-discovery"),
            "http_methods_investigated": done("http-method-handling"),
            "auth_states_compared": done("authentication"),
            "authz_boundaries_tested": done("authorization"),
            "multiple_roles_evaluated": done("horizontal-privesc")
                                        and done("vertical-privesc"),
            "object_ids_evaluated": done("idor-bola"),
            "apis_assessed": done("api-security"),
            "business_workflows_tested": done("business-logic"),
            "input_classes_evaluated": done("injection-classes"),
            "client_side_analyzed": done("javascript-analysis"),
            "new_endpoints_evaluated": inv.all_tested(),
            "related_patterns_investigated": done("attack-path-analysis"),
            "attack_paths_evaluated": done("attack-path-analysis"),
            "findings_verified": done("retesting"),
            "no_untested_areas": cl.is_fully_covered(),
        }
        unmet = [k for k, ok in checks.items() if not ok]
        return CoverageResult(
            ready=not unmet,
            coverage_ratio=cl.coverage_ratio(),
            unmet=unmet,
            checks=checks,
        )

    def can_finalize(self) -> Tuple[bool, List[str]]:
        """A final report is allowed only under a legitimate stop (§17):
        sufficient coverage, an explicit limitation, or a safety boundary."""
        if self.stopped in (StopReason.EXPLICIT_LIMITATION,
                            StopReason.SAFETY_BOUNDARY):
            return True, []
        cov = self.coverage_audit()
        return cov.ready, cov.unmet

    # ── Reporting helpers ──────────────────────
    def _record(self, event: str, **data) -> None:
        self._log.append({"t": round(time.time() - self.started_at, 2),
                          "phase": self.phase.value, "event": event, **data})

    def state(self) -> Dict[str, Any]:
        cov = self.coverage_audit()
        return {
            "target": self.target,
            "scope_loaded": self.scope_loaded,
            "phase": self.phase.value,
            "elapsed_s": round(time.time() - self.started_at, 1),
            "findings": len(self.findings),
            "coverage_ratio": cov.coverage_ratio,
            "coverage_ready": cov.ready,
            "coverage_unmet": cov.unmet,
            "checklist": self.checklist.counts(),
            "inventory": self.inventory.counts_by_kind(),
            "stopped": self.stopped.value if self.stopped else None,
            "stop_note": self.stop_note,
        }

    def log(self) -> List[Dict[str, Any]]:
        return list(self._log)
