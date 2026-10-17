"""Tests for CLI scope enforcement in HydraEngine (fail-closed gate)."""

import asyncio
import json
import os
import tempfile

import pytest

from hydra.main import HydraEngine


@pytest.fixture
def scope_file():
    scope = {
        "program": "test-prog", "platform": "custom",
        "in_scope": [{"asset": "*.example.com"}, {"asset": "example.com"}],
        "out_of_scope": [{"asset": "admin.example.com"}],
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(scope).encode())
    os.close(fd)
    yield path
    os.unlink(path)


def _engine(target, **kw):
    e = HydraEngine(target=target, workflow="quick_recon", **kw)
    asyncio.run(e._load_scope())
    return e


class TestScopeGate:
    def test_no_scope_fails_closed(self):
        e = _engine("example.com")
        assert e._scope.is_loaded is False
        assert e._scope_ok("example.com") is False    # refused

    def test_allow_no_scope_override(self):
        e = _engine("example.com", allow_no_scope=True)
        assert e._scope_ok("example.com") is True

    def test_in_scope_allowed(self, scope_file):
        e = _engine("www.example.com", scope_file=scope_file)
        assert e._scope.is_loaded is True
        assert e._scope_ok("www.example.com") is True   # wildcard
        assert e._scope_ok("example.com") is True        # apex

    def test_out_of_scope_blocked(self, scope_file):
        e = _engine("admin.example.com", scope_file=scope_file)
        assert e._scope_ok("admin.example.com") is False
        assert "admin.example.com" in e._blocked

    def test_unknown_domain_blocked(self, scope_file):
        e = _engine("evil.com", scope_file=scope_file)
        assert e._scope_ok("evil.com") is False

    def test_bad_scope_file_stays_fail_closed(self):
        e = _engine("example.com", scope_file="/does/not/exist.json")
        assert e._scope.is_loaded is False
        assert e._scope_ok("example.com") is False


class TestRunGate:
    def test_run_refuses_without_scope(self):
        e = HydraEngine(target="example.com", workflow="quick_recon")
        asyncio.run(e._load_scope())
        # run() should short-circuit before dispatching a workflow.
        e._start_time = 0.0
        result = asyncio.run(e.run())
        assert result.get("error") == "no_scope"

    def test_run_blocks_out_of_scope_primary(self, scope_file):
        e = HydraEngine(target="evil.com", workflow="quick_recon",
                        scope_file=scope_file)
        asyncio.run(e._load_scope())
        e._start_time = 0.0
        result = asyncio.run(e.run())
        assert result.get("error") == "out_of_scope"
