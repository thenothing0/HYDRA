"""Live red-team assessment checklist (doctrine §3).

Tracks every applicable testing area through the engagement. An area is only
allowed to be marked ``DONE`` after it has actually been evaluated, or ``NA``
when explicitly not applicable — this is what the coverage audit (doctrine §16)
enforces before a final report may be produced.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class AreaStatus(str, Enum):
    PENDING = "pending"          # not yet evaluated
    IN_PROGRESS = "in_progress"  # actively being tested
    DONE = "done"                # evaluated (with or without a finding)
    NA = "na"                    # explicitly not applicable
    BLOCKED = "blocked"          # could not be evaluated (limitation)


# Canonical testing areas from doctrine §3. Grouped for reporting.
TEST_AREAS: Dict[str, List[str]] = {
    "recon": [
        "reconnaissance", "asset-discovery", "technology-identification",
        "endpoint-discovery", "javascript-analysis",
    ],
    "authentication": [
        "authentication", "registration", "password-reset",
        "email-verification", "mfa", "session-management",
        "oauth-oidc", "jwt",
    ],
    "authorization": [
        "authorization", "idor-bola", "horizontal-privesc",
        "vertical-privesc", "cross-user-access", "cross-tenant-access",
        "admin-functionality",
    ],
    "api": [
        "api-security", "graphql", "http-method-handling",
        "parameter-manipulation", "mass-assignment",
    ],
    "injection": [
        "injection-classes", "ssrf", "path-traversal", "xss",
        "file-upload-download",
    ],
    "logic": [
        "business-logic", "race-conditions", "csrf", "cors",
        "rate-limiting",
    ],
    "exposure": [
        "information-disclosure", "sensitive-data-exposure",
        "cloud-storage-exposure", "websockets",
    ],
    "synthesis": [
        "attack-path-analysis", "retesting", "final-coverage-verification",
    ],
}

# Flat, ordered list of all area slugs.
ALL_AREAS: List[str] = [a for group in TEST_AREAS.values() for a in group]


@dataclass
class AreaRecord:
    slug: str
    group: str
    status: AreaStatus = AreaStatus.PENDING
    note: str = ""
    updated_at: float = field(default_factory=time.time)


class Checklist:
    """The live testing checklist with per-area status."""

    def __init__(self):
        self._areas: Dict[str, AreaRecord] = {}
        for group, slugs in TEST_AREAS.items():
            for slug in slugs:
                self._areas[slug] = AreaRecord(slug=slug, group=group)

    # ── Mutations ──────────────────────────────
    def set(self, slug: str, status: AreaStatus, note: str = "") -> AreaRecord:
        """Update an area's status. Unknown slugs are added ad-hoc so newly
        discovered functionality can be tracked without a code change."""
        if isinstance(status, str):
            status = AreaStatus(status)
        rec = self._areas.get(slug)
        if rec is None:
            rec = AreaRecord(slug=slug, group="ad-hoc")
            self._areas[slug] = rec
        rec.status = status
        if note:
            rec.note = note
        rec.updated_at = time.time()
        return rec

    def start(self, slug: str, note: str = "") -> AreaRecord:
        return self.set(slug, AreaStatus.IN_PROGRESS, note)

    def done(self, slug: str, note: str = "") -> AreaRecord:
        return self.set(slug, AreaStatus.DONE, note)

    def na(self, slug: str, note: str = "") -> AreaRecord:
        return self.set(slug, AreaStatus.NA, note)

    def blocked(self, slug: str, note: str = "") -> AreaRecord:
        return self.set(slug, AreaStatus.BLOCKED, note)

    # ── Queries ────────────────────────────────
    def get(self, slug: str) -> Optional[AreaRecord]:
        return self._areas.get(slug)

    def pending(self) -> List[str]:
        """Areas still needing evaluation (pending or in-progress)."""
        return [s for s, r in self._areas.items()
                if r.status in (AreaStatus.PENDING, AreaStatus.IN_PROGRESS)]

    def evaluated(self) -> List[str]:
        """Areas that count as covered (done / na / blocked)."""
        return [s for s, r in self._areas.items()
                if r.status in (AreaStatus.DONE, AreaStatus.NA, AreaStatus.BLOCKED)]

    def is_fully_covered(self) -> bool:
        """True when no area remains pending or in-progress."""
        return not self.pending()

    def coverage_ratio(self) -> float:
        total = len(self._areas)
        return round(len(self.evaluated()) / total, 3) if total else 1.0

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {s.value: 0 for s in AreaStatus}
        for r in self._areas.values():
            out[r.status.value] += 1
        return out

    def to_dict(self) -> Dict[str, Dict[str, str]]:
        return {
            s: {"group": r.group, "status": r.status.value, "note": r.note}
            for s, r in self._areas.items()
        }
