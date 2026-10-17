"""Tests for the write-up ingest subsystem (offline — no network)."""

import asyncio
import json

import pytest

from hydra.ingest.base import (
    SourceAdapter, Writeup, register, REGISTRY,
    classify_category, classify_severity,
)
from hydra.ingest.pipeline import IngestPipeline
from hydra.ingest.sources.medium import MediumAdapter


def _run(coro):
    return asyncio.run(coro)


class TestClassification:
    def test_category_detection(self):
        assert classify_category("a blind SQL injection in id") == "sqli"
        assert classify_category("server-side request forgery to metadata") == "ssrf"
        assert classify_category("just a normal article") == "misc"

    def test_severity_detection(self):
        assert classify_severity("this is a critical bug") == "critical"
        assert classify_severity("no severity mentioned") == "medium"


class TestMediumParser:
    RSS = """<rss><channel>
    <item><title><![CDATA[Critical SSRF in Acme]]></title>
    <link>https://medium.com/p/a</link>
    <dc:creator><![CDATA[alice]]></dc:creator>
    <content:encoded><![CDATA[<p>server-side request forgery, critical impact</p>]]></content:encoded>
    <category>ssrf</category></item>
    <item><title><![CDATA[Stored XSS]]></title>
    <link>https://medium.com/p/b</link>
    <content:encoded><![CDATA[<p>cross-site scripting, high</p>]]></content:encoded>
    <category>xss</category></item>
    </channel></rss>"""

    def test_parses_items(self):
        ws = MediumAdapter()._parse_rss(self.RSS, 10)
        assert len(ws) == 2
        assert ws[0].category == "ssrf" and ws[0].severity == "critical"
        assert ws[0].author == "alice"
        assert "<" not in ws[0].content   # HTML stripped

    def test_respects_limit(self):
        assert len(MediumAdapter()._parse_rss(self.RSS, 1)) == 1

    def test_skips_items_without_link(self):
        rss = "<rss><item><title><![CDATA[No link]]></title></item></rss>"
        assert MediumAdapter()._parse_rss(rss, 10) == []


class TestWriteup:
    def test_doc_id_stable(self):
        w1 = Writeup(source="s", title="t", url="https://x/1")
        w2 = Writeup(source="s", title="different", url="https://x/1")
        assert w1.doc_id() == w2.doc_id()   # id depends on source+url only

    def test_to_dict_roundtrips(self):
        w = Writeup(source="medium", title="t", url="u", category="xss")
        d = w.to_dict()
        assert d["category"] == "xss" and d["source"] == "medium"


@register
class _FixtureSource(SourceAdapter):
    name = "_fixture"

    async def fetch(self, query="", limit=20):
        rows = [
            ("SSRF metadata", "server-side request forgery to metadata", "ssrf", "critical"),
            ("Blind SSRF", "internal request forgery via webhook", "ssrf", "high"),
            ("Stored XSS", "cross-site scripting persisted", "xss", "high"),
            ("Reflected XSS", "cross site scripting reflected", "xss", "medium"),
            ("Union SQLi", "sql injection in id", "sqli", "critical"),
            ("Blind SQLi", "time based blind sql injection", "sqli", "high"),
        ]
        return [Writeup(source=self.name, title=t, url=f"https://x/{i}",
                        content=c, category=cat, severity=sev)
                for i, (t, c, cat, sev) in enumerate(rows)][:limit]


class TestExploitDBAdapter:
    """Offline tests for the Exploit-DB metadata adapter."""

    CSV = (
        "id,file,description,date_published,author,type,platform,port,"
        "date_added,date_updated,verified,codes,aliases,screenshot_url,"
        "application_url,source_url\n"
        "50001,x.py,Acme CMS 1.0 - Remote Code Execution,2024-01-01,alice,"
        "webapps,php,,,,1,CVE-2024-1111;OSVDB-1,,,,\n"
        "49000,y.txt,Foo 2.0 - Local Privilege Escalation,2023-06-01,bob,"
        "local,linux,,,,0,,,,,\n"
    )

    def test_registered(self):
        assert "exploitdb" in REGISTRY

    def test_parses_metadata_newest_first(self):
        from hydra.ingest.sources.exploitdb import ExploitDBAdapter

        class _Mock(ExploitDBAdapter):
            async def _get(self, url, headers=None, as_json=False):
                return TestExploitDBAdapter.CSV

        ws = _run(_Mock().fetch(limit=10))
        assert len(ws) == 2
        # Highest id first
        assert ws[0].url.endswith("/50001")
        assert ws[0].category == "rce"
        assert "CVE-2024-1111" in ws[0].tags
        # webapps + CVE lifts medium→high
        assert ws[0].severity in ("high", "critical")

    def test_query_filter(self):
        from hydra.ingest.sources.exploitdb import ExploitDBAdapter

        class _Mock(ExploitDBAdapter):
            async def _get(self, url, headers=None, as_json=False):
                return TestExploitDBAdapter.CSV

        ws = _run(_Mock().fetch(query="privilege", limit=10))
        assert len(ws) == 1 and "Privilege" in ws[0].title

    def test_empty_csv_is_safe(self):
        from hydra.ingest.sources.exploitdb import ExploitDBAdapter

        class _Mock(ExploitDBAdapter):
            async def _get(self, url, headers=None, as_json=False):
                return None

        assert _run(_Mock().fetch(limit=10)) == []


class TestIngestPipeline:
    def test_registry_has_builtin_sources(self):
        assert "github" in REGISTRY and "medium" in REGISTRY
        assert "hackerone" in REGISTRY and "exploitdb" in REGISTRY

    def test_fetch_and_save_corpus(self, tmp_path):
        pipe = IngestPipeline(corpus_dir=str(tmp_path / "corpus"))
        ws = _run(pipe.fetch(["_fixture"], limit_per_source=10))
        assert len(ws) == 6
        info = pipe.save_corpus(ws)
        assert info["added"] == 6 and info["total"] == 6
        # Re-saving the same items adds nothing (dedup by doc_id)
        info2 = pipe.save_corpus(ws)
        assert info2["added"] == 0 and info2["total"] == 6
        corpus = json.loads((tmp_path / "corpus" / "corpus.json").read_text(encoding="utf-8"))
        assert len(corpus) == 6

    def test_unknown_source_skipped(self, tmp_path):
        pipe = IngestPipeline(corpus_dir=str(tmp_path / "corpus"))
        ws = _run(pipe.fetch(["does-not-exist"], limit_per_source=5))
        assert ws == []

    def test_kev_enrichment_flags_known_exploited(self, tmp_path, monkeypatch):
        import hydra.exploits.intel as intel_mod
        pipe = IngestPipeline(corpus_dir=str(tmp_path / "corpus"))

        # Stub the KEV catalog so no network is touched.
        async def fake_kev(self):
            self._kev = {"CVE-2021-44228": {"cveID": "CVE-2021-44228"}}
            return self._kev
        monkeypatch.setattr(intel_mod.ExploitIntel, "_load_kev", fake_kev)

        ws = [
            Writeup(source="t", title="Log4Shell CVE-2021-44228 RCE",
                    url="u1", content="jndi", severity="high"),
            Writeup(source="t", title="Some info leak", url="u2",
                    content="no cve here", severity="low"),
        ]
        res = _run(pipe.enrich_with_kev(ws))
        assert res["known_exploited"] == 1
        assert "known-exploited" in ws[0].tags
        assert "kev:CVE-2021-44228" in ws[0].tags
        assert ws[0].severity == "critical"      # lifted
        assert "known-exploited" not in ws[1].tags

    @pytest.mark.skipif(
        __import__("hydra.ml", fromlist=["torch_available"]).torch_available() is False,
        reason="PyTorch not installed",
    )
    def test_train_from_writeups(self, tmp_path, monkeypatch):
        # Isolate model output to tmp
        from hydra.config import get_config
        monkeypatch.setattr(get_config().ml, "model_dir", str(tmp_path / "models"))
        pipe = IngestPipeline(corpus_dir=str(tmp_path / "corpus"))
        ws = _run(pipe.fetch(["_fixture"], limit_per_source=10))
        result = pipe.train_vuln_classifier(ws)
        assert result["trained"] is True
        assert set(result["classes"]) == {"ssrf", "xss", "sqli"}


class TestHackerOneAdapter:
    """Offline tests for the HackerOne Hacktivity adapter."""

    RESP = {"data": {"search": {
        "total_count": 2,
        "nodes": [
            {"__typename": "HacktivityDocument", "id": "1",
             "severity_rating": "critical",
             "reporter": {"username": "alice"},
             "team": {"handle": "acme", "name": "Acme"},
             "latest_disclosable_activity_at": "2025-09-01T00:00:00Z",
             "report": {"title": "SSRF in image proxy",
                        "url": "https://hackerone.com/reports/111",
                        "substate": "resolved",
                        "weakness": {"name": "Server-Side Request Forgery"}}},
            # Undisclosed / bounty-only item: no public report → skipped.
            {"__typename": "HacktivityDocument", "id": "3",
             "severity_rating": "low", "team": {"handle": "x"},
             "report": None},
        ]}}}

    def test_registered(self):
        from hydra.ingest.base import REGISTRY
        assert "hackerone" in REGISTRY

    def test_extracts_and_skips_undisclosed(self):
        from hydra.ingest.sources.hackerone import HackerOneAdapter
        a = HackerOneAdapter()
        nodes = a._extract_items(self.RESP)
        assert len(nodes) == 2
        ws = [w for w in (a._node_to_writeup(n) for n in nodes) if w]
        assert len(ws) == 1                       # undisclosed skipped
        assert ws[0].category == "ssrf" and ws[0].severity == "critical"
        assert "<" not in ws[0].content           # HTML stripped
        assert ws[0].author == "alice"

    def test_total_count_read(self):
        from hydra.ingest.sources.hackerone import HackerOneAdapter
        assert HackerOneAdapter()._total_count(self.RESP) == 2

    def test_malformed_response_is_safe(self):
        from hydra.ingest.sources.hackerone import HackerOneAdapter
        a = HackerOneAdapter()
        assert a._extract_items({"unexpected": True}) is None
        assert a._extract_items(None) is None
        assert a._total_count({}) == 0

    def test_pagination_walks_pages(self):
        import asyncio
        from hydra.ingest.sources.hackerone import HackerOneAdapter

        TOTAL = 250

        class _Mock(HackerOneAdapter):
            def __init__(self):
                super().__init__()
                self.calls = 0

            async def _post_json(self, url, payload, headers=None, retries=3):
                self.calls += 1
                offset = payload["variables"]["from"]
                size = payload["variables"]["size"]
                nodes = [
                    {"__typename": "HacktivityDocument", "id": str(offset + i),
                     "severity_rating": "high",
                     "reporter": {"username": "u"}, "team": {"handle": "t"},
                     "report": {"title": f"SQLi {offset + i}",
                                "url": f"https://h/{offset + i}",
                                "weakness": {"name": "SQL Injection"}}}
                    for i in range(size)
                    if offset + i < TOTAL
                ]
                return {"data": {"search": {"total_count": TOTAL, "nodes": nodes}}}

        m = _Mock()
        ws = asyncio.run(m.fetch(query="", limit=150))
        assert m.calls >= 2                        # walked multiple pages
        assert len(ws) == 150                      # respects the limit
        assert len({w.url for w in ws}) == 150     # all unique
