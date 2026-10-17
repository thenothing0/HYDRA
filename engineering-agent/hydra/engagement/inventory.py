"""Live attack-surface inventory (doctrine §2).

Continuously updated as the engagement discovers new functionality. Each newly
added asset/endpoint starts untested; the engagement loop is responsible for
evaluating it and marking it tested so the coverage audit can see it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Inventory item kinds from doctrine §2.
ITEM_KINDS = (
    "domain", "subdomain", "application", "api", "api_version", "endpoint",
    "parameter", "header", "auth_state", "role", "object_id", "websocket",
    "graphql", "oauth", "integration", "cloud_storage",
)


@dataclass
class SurfaceItem:
    key: str                      # stable identity within its kind
    kind: str
    label: str = ""
    auth_required: Optional[bool] = None
    authz_required: Optional[bool] = None
    tested: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)


class AttackSurfaceInventory:
    """The evolving map of everything in the authorized scope."""

    def __init__(self):
        # kind → {key → SurfaceItem}
        self._items: Dict[str, Dict[str, SurfaceItem]] = {}

    def add(self, kind: str, key: str, label: str = "",
            **properties) -> SurfaceItem:
        """Add or update an item. Returns the (possibly pre-existing) item.

        Re-adding a known key updates its label/properties but preserves its
        `tested` flag and discovery time — discovery is idempotent.
        """
        bucket = self._items.setdefault(kind, {})
        item = bucket.get(key)
        if item is None:
            item = SurfaceItem(key=key, kind=kind, label=label or key)
            bucket[key] = item
        elif label:
            item.label = label
        if properties:
            item.properties.update(properties)
        return item

    def mark_tested(self, kind: str, key: str, tested: bool = True) -> bool:
        item = self._items.get(kind, {}).get(key)
        if item is None:
            return False
        item.tested = tested
        return True

    def set_auth(self, kind: str, key: str,
                 auth_required: Optional[bool] = None,
                 authz_required: Optional[bool] = None) -> bool:
        item = self._items.get(kind, {}).get(key)
        if item is None:
            return False
        if auth_required is not None:
            item.auth_required = auth_required
        if authz_required is not None:
            item.authz_required = authz_required
        return True

    # ── Queries ────────────────────────────────
    def items(self, kind: Optional[str] = None) -> List[SurfaceItem]:
        if kind is not None:
            return list(self._items.get(kind, {}).values())
        return [it for bucket in self._items.values() for it in bucket.values()]

    def untested(self, kind: Optional[str] = None) -> List[SurfaceItem]:
        return [it for it in self.items(kind) if not it.tested]

    def count(self, kind: Optional[str] = None) -> int:
        return len(self.items(kind))

    def counts_by_kind(self) -> Dict[str, int]:
        return {k: len(v) for k, v in self._items.items() if v}

    def all_tested(self) -> bool:
        """True when every discovered item has been evaluated."""
        return not self.untested()

    # ── Bulk ingest from a HYDRA recon dict ────
    def ingest_recon(self, target: str, recon: Dict[str, Any]) -> Dict[str, int]:
        """Populate the inventory from a recon_data dict (subdomains,
        live_hosts, endpoints). Returns how many items were added per kind."""
        before = self.count()
        self.add("domain", target, target, role="primary_target")
        for sub in recon.get("subdomains", []) or []:
            self.add("subdomain", sub, sub)
        for host in recon.get("live_hosts", []) or []:
            self.add("application", host, host)
        for ep in recon.get("endpoints", []) or []:
            self.add("endpoint", ep, ep[:120])
        added = self.count() - before
        return {"added": added, "total": self.count()}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts_by_kind(),
            "total": self.count(),
            "untested": len(self.untested()),
            "items": [
                {"kind": it.kind, "key": it.key, "label": it.label,
                 "tested": it.tested, "auth_required": it.auth_required,
                 "authz_required": it.authz_required}
                for it in self.items()
            ],
        }
