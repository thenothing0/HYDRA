"""Tests for the continuous red-team engagement state machine (doctrine)."""

import pytest

from hydra.engagement import (
    Engagement, Phase, StopReason, Checklist, AreaStatus,
    AttackSurfaceInventory, ALL_AREAS,
)
from hydra.prompts import red_team_doctrine, load_doctrine


class TestChecklist:
    def test_starts_all_pending(self):
        cl = Checklist()
        assert len(cl.pending()) == len(ALL_AREAS)
        assert cl.evaluated() == []
        assert cl.is_fully_covered() is False

    def test_done_and_na_count_as_covered(self):
        cl = Checklist()
        cl.done("authentication")
        cl.na("websockets", note="no ws in app")
        cl.blocked("mfa", note="no test account")
        ev = cl.evaluated()
        assert "authentication" in ev and "websockets" in ev and "mfa" in ev
        assert "authentication" not in cl.pending()

    def test_unknown_area_tracked_adhoc(self):
        cl = Checklist()
        rec = cl.done("graphql-batching-abuse")
        assert rec.group == "ad-hoc"
        assert "graphql-batching-abuse" in cl.evaluated()

    def test_coverage_ratio(self):
        cl = Checklist()
        assert cl.coverage_ratio() == 0.0
        for a in ALL_AREAS:
            cl.done(a)
        assert cl.coverage_ratio() == 1.0
        assert cl.is_fully_covered() is True


class TestInventory:
    def test_add_is_idempotent_and_preserves_tested(self):
        inv = AttackSurfaceInventory()
        inv.add("endpoint", "/api/users", "Users")
        inv.mark_tested("endpoint", "/api/users")
        inv.add("endpoint", "/api/users", "Users v2")   # re-discovery
        item = inv.items("endpoint")[0]
        assert item.tested is True                        # preserved
        assert item.label == "Users v2"                   # updated
        assert inv.count("endpoint") == 1

    def test_untested_and_all_tested(self):
        inv = AttackSurfaceInventory()
        inv.add("endpoint", "/a")
        inv.add("endpoint", "/b")
        assert inv.all_tested() is False
        assert len(inv.untested()) == 2
        inv.mark_tested("endpoint", "/a")
        inv.mark_tested("endpoint", "/b")
        assert inv.all_tested() is True

    def test_ingest_recon(self):
        inv = AttackSurfaceInventory()
        res = inv.ingest_recon("example.com", {
            "subdomains": ["a.example.com", "b.example.com"],
            "live_hosts": ["https://a.example.com"],
            "endpoints": ["https://a.example.com/x"],
        })
        assert res["added"] >= 4
        assert inv.count("subdomain") == 2
        assert inv.count("application") == 1
        assert inv.count("endpoint") == 1


class TestEngagementLoop:
    def test_phase_advances_in_order(self):
        eng = Engagement("example.com")
        assert eng.phase == Phase.DISCOVER
        eng.advance()
        assert eng.phase == Phase.INVENTORY

    def test_finding_is_not_a_stop(self):
        eng = Engagement("example.com")
        eng.record_finding({"name": "SQLi", "severity": "critical"})
        assert eng.is_active() is True          # a finding never stops the loop
        assert len(eng.findings) == 1

    def test_coverage_review_routes_back_to_test_when_incomplete(self):
        eng = Engagement("example.com")
        eng.phase = Phase.COVERAGE_REVIEW
        nxt = eng.advance()
        assert nxt == Phase.TEST                 # not ready → keep testing

    def test_coverage_review_routes_to_retest_when_complete(self):
        eng = Engagement("example.com")
        for a in ALL_AREAS:
            eng.checklist.done(a)
        eng.inventory.add("endpoint", "/a")
        eng.inventory.mark_tested("endpoint", "/a")
        eng.phase = Phase.COVERAGE_REVIEW
        nxt = eng.advance()
        assert nxt == Phase.RETEST

    def test_cannot_finalize_without_coverage(self):
        eng = Engagement("example.com")
        ok, unmet = eng.can_finalize()
        assert ok is False
        assert unmet                              # lists the missing checks

    def test_finalize_allowed_on_full_coverage(self):
        eng = Engagement("example.com")
        for a in ALL_AREAS:
            eng.checklist.done(a)
        eng.inventory.add("endpoint", "/a")
        eng.inventory.mark_tested("endpoint", "/a")
        ok, unmet = eng.can_finalize()
        assert ok is True and unmet == []

    def test_finalize_allowed_on_explicit_limitation(self):
        eng = Engagement("example.com")
        eng.stop(StopReason.EXPLICIT_LIMITATION, note="auth unavailable")
        ok, _ = eng.can_finalize()
        assert ok is True                         # §17-B legitimate stop
        assert eng.is_active() is False

    def test_finalize_allowed_on_safety_boundary(self):
        eng = Engagement("example.com")
        eng.stop(StopReason.SAFETY_BOUNDARY, note="would be destructive")
        ok, _ = eng.can_finalize()
        assert ok is True                         # §17-C legitimate stop

    def test_state_snapshot_shape(self):
        eng = Engagement("example.com", scope_loaded=True)
        eng.checklist.done("reconnaissance")
        st = eng.state()
        assert st["target"] == "example.com"
        assert st["scope_loaded"] is True
        assert 0.0 < st["coverage_ratio"] < 1.0
        assert "coverage_unmet" in st


class TestDoctrine:
    def test_red_team_doctrine_loads(self):
        text = red_team_doctrine()
        assert "CONTINUOUS RED-TEAM TESTING" in text
        assert "STOPPING CONDITIONS" in text

    def test_unknown_doctrine_raises(self):
        with pytest.raises(FileNotFoundError):
            load_doctrine("does-not-exist")
