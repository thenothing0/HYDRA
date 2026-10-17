"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Engagement — Continuous Red-Team Testing State Machine ║
║    Turns the red-team doctrine (the DISCOVER→…→REPORT loop,   ║
║    the live checklist, the attack-surface inventory, the      ║
║    coverage audit and the stopping conditions) into code that ║
║    drives an authorized engagement instead of just prose.     ║
╚══════════════════════════════════════════════════════════════╝

A confirmed finding is an event inside the loop, never a stopping condition.
Only sufficient coverage, an explicit limitation, or a safety boundary stops
an engagement — enforced by `Engagement.can_finalize()`.
"""

from hydra.engagement.checklist import (
    Checklist, AreaStatus, AreaRecord, TEST_AREAS, ALL_AREAS,
)
from hydra.engagement.inventory import AttackSurfaceInventory, SurfaceItem, ITEM_KINDS
from hydra.engagement.loop import (
    Engagement, Phase, PHASE_ORDER, StopReason, CoverageResult,
)

__all__ = [
    "Checklist", "AreaStatus", "AreaRecord", "TEST_AREAS", "ALL_AREAS",
    "AttackSurfaceInventory", "SurfaceItem", "ITEM_KINDS",
    "Engagement", "Phase", "PHASE_ORDER", "StopReason", "CoverageResult",
]
