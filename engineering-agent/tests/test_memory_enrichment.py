"""Tests for scan-time context enrichment from semantic memory."""

import asyncio

import pytest

from hydra.main import HydraEngine


class _FakeMemory:
    """Stand-in for SemanticMemory returning canned hits."""

    def __init__(self, hits):
        self._hits = hits

    async def initialize(self):
        return None

    async def search(self, collection, query, top_k=5):
        # Return hits relevant to the query's leading keyword.
        return self._hits.get(collection, [])[:top_k]


def _hit(url, source, category, sim, title):
    return {"document": f"{title}\nbody", "similarity": sim,
            "metadata": {"url": url, "source": source,
                         "category": category, "severity": "high"}}


def _patch_memory(monkeypatch, hits):
    import hydra.memory.semantic as sm
    monkeypatch.setattr(sm, "SemanticMemory", lambda *a, **k: _FakeMemory(hits))


def _engine():
    return HydraEngine(target="example.com", workflow="quick_recon",
                       allow_no_scope=True)


class TestMemoryEnrichment:
    def test_attaches_similar_writeups(self, monkeypatch):
        _patch_memory(monkeypatch, {"methodologies": [
            _hit("https://h1/1", "hackerone", "ssrf", 0.72, "SSRF in proxy"),
            _hit("https://h1/2", "hackerone", "ssrf", 0.61, "Blind SSRF"),
        ]})
        e = _engine()
        e.findings = [{"name": "SSRF in webhook", "type": "ssrf"}]
        asyncio.run(e._enrich_from_memory())
        sw = e.findings[0]["similar_writeups"]
        assert len(sw) == 2
        assert sw[0]["url"] == "https://h1/1"
        assert sw[0]["source"] == "hackerone"
        assert sw[0]["similarity"] == 0.72

    def test_filters_below_min_similarity(self, monkeypatch):
        _patch_memory(monkeypatch, {"methodologies": [
            _hit("https://h1/1", "hackerone", "rce", 0.80, "good match"),
            _hit("https://h1/2", "exploitdb", "rce", 0.10, "weak match"),
        ]})
        e = _engine()
        e.findings = [{"name": "RCE", "type": "rce"}]
        asyncio.run(e._enrich_from_memory(min_similarity=0.35))
        sw = e.findings[0]["similar_writeups"]
        assert len(sw) == 1 and sw[0]["url"] == "https://h1/1"

    def test_no_hits_leaves_finding_clean(self, monkeypatch):
        _patch_memory(monkeypatch, {"methodologies": []})
        e = _engine()
        e.findings = [{"name": "Something", "type": "misc"}]
        asyncio.run(e._enrich_from_memory())
        assert "similar_writeups" not in e.findings[0]

    def test_empty_findings_is_safe(self, monkeypatch):
        _patch_memory(monkeypatch, {"methodologies": [
            _hit("https://h1/1", "hackerone", "ssrf", 0.9, "x")]})
        e = _engine()
        e.findings = []
        asyncio.run(e._enrich_from_memory())      # no crash
        assert e.findings == []

    def test_report_renders_similar_writeups(self):
        from hydra.reporting import AdvancedReportEngine
        rg = AdvancedReportEngine()
        finding = {"name": "SSRF", "severity": "high",
                   "similar_writeups": [
                       {"title": "SSRF in proxy", "url": "https://h1/1",
                        "source": "hackerone", "category": "ssrf",
                        "severity": "high", "similarity": 0.72}]}
        enriched = rg._enrich_finding(finding, 1)
        md = rg._render_markdown({
            "meta": {"target": "t", "scan_id": "s", "generated_at": "now",
                     "total_findings": 1,
                     "severity_breakdown": {"critical": 0, "high": 1,
                                            "medium": 0, "low": 0, "info": 0}},
            "executive_summary": "x", "findings": [enriched],
            "attack_chains": []})
        assert "Similar disclosed reports" in md
        assert "https://h1/1" in md
        assert "hackerone" in md
