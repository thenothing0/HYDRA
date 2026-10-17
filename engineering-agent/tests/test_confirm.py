"""Offline tests for the human-gated benign confirmation module (Part 2).

``hydra/hunt/confirm.py`` is the depth-first, operator-invoked counterpart to the
autonomous ``hunt`` loop. It raises ONE finding's evidence using **benign proofs
only** — a controlled differential + a deliberate repeat (→ REPRODUCED) or an
out-of-band callback to a host the operator owns (SSRF). These tests lock in that
it never sends an exploitation payload, that reflection stays a LEAD, and that
dangerous classes honestly report "manual verification required".

Every request is injected (no socket) via the same RecordingFetch/_Scope fakes
used by test_hunt.py.
"""

import asyncio
from urllib.parse import unquote

import pytest

from hydra.hunt.confirm import (
    ConfirmationEngine, ConfirmationResult, ProbeExchange, _NO_BENIGN_PROOF,
    _NEXT_MW_HEADER, _NEXT_MW_VALUES, _SAP_UPLOADER_PATH, _HDR_REFLECT_NAME,
    _VITE_DENY_CANARIES, _VITE_BYPASS_SUFFIXES,
    _IMG_ACCEPT_A, _IMG_ACCEPT_B, _IMG_VARY_HEADER, _NEXT_IMAGE_PATH,
    _RR_PRERENDER_HEADER, _RR_ROUTE_IDS,
    _K8S_HEALTHZ_PATH, _K8S_WEBHOOK_PATH,
    _WORSTFIT_SOFT_HYPHEN, _WORSTFIT_FLAGS, _WORSTFIT_PHP_PATHS,
    _DANGEROUS_WRITE_METHODS, _PARTIAL_PUT_METHOD, _TOMCAT_SERVER_RE,
)
from hydra.hunt.safety import (
    EvidenceLevel, is_exploitation_payload, is_safe_probe_header,
)
from hydra.hunt.prober import SafeProber


def _run(coro):
    return asyncio.run(coro)


def _decode(url: str) -> str:
    """Fully percent-decode a probe URL so a responder can read the sent value
    regardless of how many encoding layers benign_probe_variants wrapped it in."""
    s = url
    for _ in range(4):
        d = unquote(s)
        if d == s:
            break
        s = d
    return s


# ── fakes (mirrors test_hunt.py) ───────────────────
class RecordingFetch:
    """Injectable async fetch(url) -> (status, headers, body); records every URL."""

    def __init__(self, responder=None):
        self.urls = []
        self._responder = responder or (lambda url: (200, {}, ""))

    async def __call__(self, url):
        self.urls.append(url)
        return self._responder(url)


class HeaderRecordingFetch:
    """Header-aware fetch: ``async fetch(url, headers=None)`` -> (status, hdrs, body).

    Two positional args, so ``SafeProber._fetch_accepts_headers()`` returns True
    and CVE-2025-29927's benign ``x-middleware-subrequest`` marker actually
    reaches the responder. The responder is called ``responder(url, headers)`` so
    a test can flip the status on header presence. Records every ``(url, hdrs)``.
    """

    def __init__(self, responder=None):
        self.calls = []
        self._responder = responder or (lambda url, headers: (200, {}, ""))

    async def __call__(self, url, headers=None):
        hdrs = dict(headers or {})
        self.calls.append((url, hdrs))
        return self._responder(url, hdrs)


class _Scope:
    """Minimal scope-engine stand-in (loaded + allow/deny by substring)."""

    def __init__(self, loaded=True, allow_host=""):
        self.is_loaded = loaded
        self._allow_host = allow_host

    def validate_target(self, host):
        from types import SimpleNamespace
        ok = (not self._allow_host) or (self._allow_host in host)
        return SimpleNamespace(allowed=ok, reason="" if ok else "oos")


def _engine(responder, scope=None, repeats=2):
    prober = SafeProber(scope_engine=scope, fetch=RecordingFetch(responder))
    return ConfirmationEngine(prober=prober, repeats=repeats), prober


# ═══════════════════════════════════════════════════
#  Differential + repeat → REPRODUCED (benign only)
# ═══════════════════════════════════════════════════
class TestDifferentialReproduction:
    def test_sqli_error_reproduced(self):
        # A DB parse error appears only when the benign quote reaches the query;
        # the numeric control is clean → error-based signal, then repeats hold.
        def responder(url):
            dec = _decode(url)
            if "id='" in dec or 'id="' in dec:
                return (200, {}, "You have an error in your SQL syntax near '")
            return (200, {}, "everything ok")
        engine, _ = _engine(responder)
        res = _run(engine.confirm("https://t.tld/", "id", "sqli"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        # control + payload + 2 deliberate repeats all recorded for the PoC
        labels = [e.label for e in res.exchanges]
        assert labels.count("repeat") == 2 and "control" in labels
        assert "curl -si" in res.poc

    def test_ssti_arithmetic_reproduced(self):
        # {{7*7}} renders to 49 (literal gone); control {{7*6}} → 42 keeps it
        # from being a page that merely contains "49".
        def responder(url):
            dec = _decode(url)
            if "7*7" in dec:
                return (200, {}, "output: 49")
            if "7*6" in dec:
                return (200, {}, "output: 42")
            return (200, {}, "output: none")
        engine, _ = _engine(responder)
        res = _run(engine.confirm("https://t.tld/", "tpl", "ssti"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert "SSTI" in res.summary

    def test_open_redirect_reproduced(self):
        # The example.com canary lands in the Location header on every send.
        def responder(url):
            return (301, {"Location": "https://example.com/hydra"}, "")
        engine, _ = _engine(responder)
        res = _run(engine.confirm("https://t.tld/", "next", "open_redirect"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED

    def test_single_hit_no_repeat_keeps_probe_evidence(self):
        # Signal fires once then the repeat does NOT re-trigger → confirmed, but
        # evidence stays at the probe's base level (not REPRODUCED).
        state = {"n": 0}

        def responder(url):
            dec = _decode(url)
            if "id='" in dec:
                state["n"] += 1
                if state["n"] == 1:                 # only the FIRST payload send
                    return (200, {}, "SQL syntax error")
            return (200, {}, "everything ok")
        engine, _ = _engine(responder)
        res = _run(engine.confirm("https://t.tld/", "id", "sqli"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.INFERRED   # base, not reproduced

    def test_no_signal_stays_unverified(self):
        engine, _ = _engine(lambda url: (200, {}, "nothing to see"))
        res = _run(engine.confirm("https://t.tld/", "id", "sqli"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED


# ═══════════════════════════════════════════════════
#  Reflection is a LEAD, never execution
# ═══════════════════════════════════════════════════
class TestReflectionStaysLead:
    def test_xss_reflection_never_confirms(self):
        # Even a perfectly reproduced verbatim echo stays UNVERIFIED: reflection
        # != execution. HYDRA will not auto-inject an executable XSS to "prove" it.
        marker = "hpr0be'\"<>"

        def responder(url):
            if marker in _decode(url):
                return (200, {}, f"echo: {marker} back")
            return (200, {}, "clean")
        engine, _ = _engine(responder)
        res = _run(engine.confirm("https://t.tld/", "q", "xss"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Reflection" in res.summary


# ═══════════════════════════════════════════════════
#  SSRF — benign out-of-band callback only
# ═══════════════════════════════════════════════════
class TestSSRFCallback:
    def test_ssrf_requires_external_callback(self):
        engine, prober = _engine(lambda url: (200, {}, ""))
        res = _run(engine.confirm("https://t.tld/", "url", "ssrf"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "callback" in res.note.lower()
        assert prober.sent == 0                    # nothing sent without a target

    def test_ssrf_arms_benign_callback(self):
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        prober = SafeProber(fetch=fetch)
        engine = ConfirmationEngine(prober=prober)
        res = _run(engine.confirm("https://t.tld/", "url", "ssrf",
                                  oob_callback="https://cb.example.net"))
        # OOB confirmation is inherently out-of-band: we ARM it (INFERRED) and
        # tell the operator to check their listener — we never claim REPRODUCED.
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.INFERRED
        assert res.technique == "OOB callback"
        assert res.exchanges and res.exchanges[0].label == "oob-callback"
        assert "nonce=" in res.exchanges[0].note
        assert len(fetch.urls) == 1                # exactly ONE benign outbound GET
        assert is_exploitation_payload(fetch.urls[0]) is False

    def test_ssrf_uses_provided_nonce(self):
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        engine = ConfirmationEngine(prober=SafeProber(fetch=fetch))
        res = _run(engine.confirm("https://t.tld/", "url", "ssrf",
                                  oob_callback="https://cb.example.net",
                                  nonce="deadbeef"))
        assert "deadbeef" in res.poc
        assert "deadbeef" in fetch.urls[0]

    @pytest.mark.parametrize("bad_callback", [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1/",
        "http://localhost:8080/",
        "file:///etc/passwd",
    ])
    def test_ssrf_refuses_internal_metadata_callback(self, bad_callback):
        # Defense-in-depth: the callback host itself must be benign & external.
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        engine = ConfirmationEngine(prober=SafeProber(fetch=fetch))
        res = _run(engine.confirm("https://t.tld/", "url", "ssrf",
                                  oob_callback=bad_callback))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Refused" in res.note
        assert fetch.urls == []                    # never transmitted


# ═══════════════════════════════════════════════════
#  Honest "no benign proof" for exploitation-only classes
# ═══════════════════════════════════════════════════
class TestNoBenignProof:
    @pytest.mark.parametrize("vc", ["rce", "lfi", "idor", "authz", "cors"])
    def test_dangerous_classes_report_manual_only(self, vc):
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        engine = ConfirmationEngine(prober=SafeProber(fetch=fetch))
        res = _run(engine.confirm("https://t.tld/", "p", vc))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert res.note == _NO_BENIGN_PROOF
        assert fetch.urls == []                    # nothing exploitation-grade sent


# ═══════════════════════════════════════════════════
#  never-exploit invariant — nothing exploitation-grade hits the wire
# ═══════════════════════════════════════════════════
class TestNeverExploitInvariant:
    def test_no_confirm_send_is_exploitation(self):
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        prober = SafeProber(fetch=fetch)
        engine = ConfirmationEngine(prober=prober)
        for vc in ("ssti", "sqli", "open_redirect", "xss"):
            _run(engine.confirm("https://t.tld/", "p", vc))
        _run(engine.confirm("https://t.tld/", "url", "ssrf",
                            oob_callback="https://cb.example.net"))
        assert fetch.urls, "expected benign probes to be sent"
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url

    def test_scope_gate_blocks_out_of_scope_confirm(self):
        # A loaded scope refuses an out-of-scope target: no request is sent.
        fetch = RecordingFetch(lambda url: (200, {}, ""))
        prober = SafeProber(scope_engine=_Scope(allow_host="in.tld"), fetch=fetch)
        engine = ConfirmationEngine(prober=prober)
        res = _run(engine.confirm("https://out.tld/", "id", "sqli"))
        assert fetch.urls == []
        assert res.confirmed is False


# ═══════════════════════════════════════════════════
#  as_dict packaging (for scans/confirmation.json + reports)
# ═══════════════════════════════════════════════════
class TestResultPackaging:
    def test_as_dict_roundtrips_exchanges(self):
        r = ConfirmationResult(
            target="https://t.tld/", param="id", vuln_class="sqli",
            confirmed=True, evidence_level=EvidenceLevel.REPRODUCED,
            exchanges=[ProbeExchange("payload", "https://t.tld/?id=%27", 200, "n")])
        d = r.as_dict()
        assert d["confirmed"] is True
        assert d["evidence_level"] == EvidenceLevel.REPRODUCED
        assert d["exchanges"][0]["label"] == "payload"
        assert d["exchanges"][0]["status"] == 200


# ═══════════════════════════════════════════════════
#  _wf_confirm — CLI-level wiring (offline)
# ═══════════════════════════════════════════════════
class TestWfConfirm:
    def test_wf_confirm_requires_param(self, tmp_path):
        from hydra.main import HydraEngine
        eng = HydraEngine(target="t.tld", workflow="confirm",
                          output_dir=str(tmp_path), confirm_param="",
                          confirm_class="sqli")
        eng._scope = None
        _run(eng._wf_confirm())
        assert eng.findings == []                  # guarded out, nothing recorded

    def test_wf_confirm_rejects_auto_class(self, tmp_path):
        from hydra.main import HydraEngine
        eng = HydraEngine(target="t.tld", workflow="confirm",
                          output_dir=str(tmp_path), confirm_param="id",
                          confirm_class="auto")
        eng._scope = None
        _run(eng._wf_confirm())
        assert eng.findings == []                  # single-target only, no 'auto'

    def test_wf_confirm_records_finding(self, tmp_path, monkeypatch):
        # Inject an offline prober into the engine the workflow builds internally.
        import hydra.hunt.confirm as confirm_mod
        from hydra.main import HydraEngine

        def responder(url):
            dec = _decode(url)
            return ((200, {}, "You have an error in your SQL syntax")
                    if "id='" in dec else (200, {}, "ok"))

        def fake_prober(scope_engine=None, rate_limiter=None):
            return SafeProber(fetch=RecordingFetch(responder))
        monkeypatch.setattr(confirm_mod, "SafeProber", fake_prober)

        eng = HydraEngine(target="t.tld", workflow="confirm",
                          output_dir=str(tmp_path), confirm_param="id",
                          confirm_class="sqli")
        eng._scope = None
        _run(eng._wf_confirm())
        assert len(eng.findings) == 1
        f = eng.findings[0]
        assert f["hunt_source"] == "confirm"
        assert f["evidence_level"] == EvidenceLevel.REPRODUCED
        assert f["severity"] == "high"             # confirmed sqli
        saved = tmp_path / "t.tld" / "scans" / "confirmation.json"
        assert saved.exists()

    def test_confirm_severity_is_honest(self):
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(target="", param="", vuln_class="sqli",
                                       confirmed=True)
        assert HydraEngine._confirm_severity("sqli", confirmed) == "high"
        assert HydraEngine._confirm_severity("open_redirect", confirmed) == "medium"
        # SSRF confirmation is always out-of-band-pending → confirmed False → info
        pending = ConfirmationResult(target="", param="", vuln_class="ssrf",
                                     confirmed=False)
        assert HydraEngine._confirm_severity("ssrf", pending) == "info"


# ═══════════════════════════════════════════════════
#  CVE-2025-29927 — Next.js middleware bypass (benign status differential)
# ═══════════════════════════════════════════════════
def _nextjs_engine(responder, scope=None, repeats=2):
    """Build a ConfirmationEngine over a header-aware fetch and expose the fake
    so a test can assert exactly which headers reached the wire."""
    fetch = HeaderRecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestNextjsConfirm:
    TARGET = "https://t.tld/admin"

    def test_gated_403_flips_to_200_is_reproduced(self):
        # Access-gated without the header, HTTP 200 with it → bypass, and the
        # deliberate repeats hold → REPRODUCED. Pure status differential; the
        # protected body is never inspected or exfiltrated.
        def responder(url, headers):
            if headers.get(_NEXT_MW_HEADER):
                return (200, {}, "admin dashboard")
            return (403, {}, "forbidden")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))

        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert res.technique == "CVE-2025-29927 middleware bypass"
        assert "reproduced on" in res.summary
        assert res.poc and _NEXT_MW_HEADER in res.poc
        # baseline sent FIRST with no bypass header…
        assert fetch.calls[0] == (self.TARGET, {})
        # …and the benign marker header actually reached the wire, with a value
        # drawn from the known CVE-2025-29927 set (never a fabricated proof).
        sent_values = [h.get(_NEXT_MW_HEADER) for _u, h in fetch.calls
                       if h.get(_NEXT_MW_HEADER)]
        assert sent_values and all(v in _NEXT_MW_VALUES for v in sent_values)
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels and "repeat" in labels

    def test_redirect_gated_baseline_flips_to_200(self):
        # A login redirect (302 + Location) is also an access gate; opening it
        # to 200 with the header is the same bypass. Exercises the redirect
        # branch of ``baseline_gated``.
        def responder(url, headers):
            if headers.get(_NEXT_MW_HEADER):
                return (200, {}, "content")
            return (302, {"Location": "https://t.tld/login"}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert res.technique == "CVE-2025-29927 middleware bypass"

    def test_ungated_baseline_not_confirmed(self):
        # If the route is already 200 unauthenticated there is no gate to bypass
        # — honestly OBSERVED / not-confirmed, and no header probe is even sent.
        def responder(url, headers):
            return (200, {}, "public page")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "not access-gated" in res.summary
        # only the baseline was sent; we never probed with the bypass header
        assert all(not h.get(_NEXT_MW_HEADER) for _u, h in fetch.calls)

    def test_gated_but_no_value_flips_not_confirmed(self):
        # Access-gated but no benign header value opens it (patched / not
        # vulnerable) → not confirmed, OBSERVED, and every known value was tried.
        def responder(url, headers):
            return (403, {}, "forbidden")   # header ignored — gate always holds
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "flipped it to HTTP 200" in res.summary
        sent_values = {h.get(_NEXT_MW_HEADER) for _u, h in fetch.calls
                       if h.get(_NEXT_MW_HEADER)}
        assert sent_values == set(_NEXT_MW_VALUES)   # exhausted the benign set

    def test_baseline_request_failure_is_unverified(self):
        # No usable baseline (status 0 / transport error) → cannot assess the
        # differential → UNVERIFIED, not a false "not vulnerable".
        def responder(url, headers):
            return (0, {}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_single_observation_is_inferred_not_reproduced(self):
        # The gate opens once but the repeat does not re-trigger → stays INFERRED
        # (a single observation is not "reproduced").
        class _FlipOnce:
            def __init__(self):
                self.hits = 0

            def __call__(self, url, headers):
                if headers.get(_NEXT_MW_HEADER):
                    self.hits += 1
                    return (200, {}, "content") if self.hits == 1 else (403, {}, "")
                return (403, {}, "forbidden")
        engine, _ = _nextjs_engine(_FlipOnce())
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.INFERRED
        assert "single observation" in res.summary

    def test_nextjs_never_needs_a_param(self):
        # The bypass is a request-HEADER differential, so confirm() must not
        # require a ``param`` for the nextjs class (unlike sqli/xss/etc.).
        def responder(url, headers):
            return (200, {}, "x") if headers.get(_NEXT_MW_HEADER) else (401, {}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs"))
        assert res.confirmed is True

    def test_nextjs_probe_headers_are_never_exploitation_grade(self):
        # Belt-and-braces: whatever headers the confirmer transmits, none is an
        # exploitation payload on name or value.
        def responder(url, headers):
            return (200, {}, "x") if headers.get(_NEXT_MW_HEADER) else (403, {}, "")
        engine, fetch = _nextjs_engine(responder)
        _run(engine.confirm(self.TARGET, "", "nextjs"))
        for _u, hdrs in fetch.calls:
            for name, value in hdrs.items():
                assert is_exploitation_payload(name) is False
                assert is_exploitation_payload(value) is False


# ═══════════════════════════════════════════════════
#  SAP NetWeaver CVE-2025-31324 — pre-auth REACHABILITY differential
#  (benign, GET-only; the metadata-uploader webshell POST is NEVER sent,
#   and the CVE-2025-42999 deserialization sink is never touched)
# ═══════════════════════════════════════════════════
def _sap_engine(responder, scope=None, repeats=2):
    """SAP is a GET-only reachability check, so the header-free RecordingFetch
    is the right fake. Returns (engine, fetch) so a test can read fetch.urls."""
    fetch = RecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestSapConfirm:
    TARGET = "https://sap.t.tld"
    NONCE = "deadbeefcafe"

    @staticmethod
    def _split(uploader, control):
        """Responder: the ``uploader`` tuple when the well-known uploader path is
        in the URL, else the ``control`` (random sibling) tuple."""
        def responder(url):
            return uploader if _SAP_UPLOADER_PATH in url else control
        return responder

    def test_reachable_unauth_is_confirmed_observed(self):
        # Uploader answers 200 without auth; a random sibling path is 404 → a
        # real reachable handler (not a catch-all) → the CVE-2025-31324 pre-auth
        # exposure precondition is present. Reachability is STATIC → OBSERVED.
        responder = self._split(
            (200, {"Server": "SAP NetWeaver Application Server"},
             "<html>SAP Visual Composer</html>"),
            (404, {}, "not found"))
        engine, fetch = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED   # never REPRODUCED
        assert res.vuln_class == "sap"
        assert "reachable WITHOUT auth" in res.summary
        assert "CVE-2025-31324" in res.summary
        assert "SAP fingerprint" in res.note
        # control sent FIRST, then the uploader, then the deliberate repeats
        assert _SAP_UPLOADER_PATH not in fetch.urls[0]
        assert _SAP_UPLOADER_PATH in fetch.urls[1]
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels
        assert labels.count("repeat") == 2

    def test_get_405_on_present_uploader_is_reachable(self):
        # A deployed uploader that rejects GET with 405 is still REACHABLE
        # without auth (it exists and answers) — distinct from the 404 sibling.
        responder = self._split((405, {}, "Method Not Allowed"), (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "HTTP 405" in res.summary

    def test_access_gated_401_is_not_confirmed(self):
        # 401 is exactly what a protected/patched NetWeaver returns → NOT the
        # unauthenticated exposure. Observed, but confirmed=False.
        responder = self._split((401, {}, "Unauthorized"), (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "access-gated" in res.summary

    def test_redirect_to_login_is_not_confirmed(self):
        # A 3xx to a login page is authentication enforced, not the exposure.
        responder = self._split(
            (302, {"Location": "https://sap.t.tld/irj/portal/login"}, ""),
            (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "access-gated" in res.summary

    def test_absent_404_reports_not_present(self):
        # 404 on the uploader → the Visual Composer servlet is not deployed.
        responder = self._split((404, {}, ""), (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "not present" in res.summary

    def test_catchall_same_status_is_not_confirmed(self):
        # If a random sibling returns the SAME status as the uploader, we can't
        # claim a specific reachable handler — indistinguishable from a catch-all.
        responder = self._split((200, {}, "generic"), (200, {}, "generic"))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "catch-all" in res.summary

    def test_endpoint_transport_failure_is_unverified(self):
        # No usable uploader response (status 0 / transport error) → cannot
        # assess reachability → UNVERIFIED, not a false "not vulnerable".
        responder = self._split((0, {}, ""), (200, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Endpoint request failed" in res.summary

    def test_sap_netweaver_alias_dispatches(self):
        # The "sap_netweaver" alias routes to the same reachability confirmer.
        responder = self._split((200, {}, "SAP"), (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap_netweaver",
                                  nonce=self.NONCE))
        assert res.vuln_class == "sap"
        assert res.technique == "CVE-2025-31324 pre-auth reachability"

    def test_sap_never_needs_a_param(self):
        # Reachability is a fixed-endpoint property, so confirm() must not
        # require a ``param`` for the sap class (like nextjs, unlike sqli).
        responder = self._split((200, {}, "SAP"), (404, {}, ""))
        engine, _ = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        assert res.confirmed is True

    def test_never_exploit_invariant_no_upload_ever(self):
        # The whole point: every send is a benign GET, none is an exploitation
        # payload, and the multipart webshell POST upload is NEVER emitted —
        # not on the wire and not in the PoC as an executable command.
        responder = self._split(
            (200, {"Server": "SAP NetWeaver"}, "Visual Composer"),
            (404, {}, ""))
        engine, fetch = _sap_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sap", nonce=self.NONCE))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url
        # exactly one uploader path per uploader send: 1 payload + 2 repeats
        assert sum(_SAP_UPLOADER_PATH in u for u in fetch.urls) == 3
        # the PoC is GET-only: no POST / multipart / body-carrying curl flags
        assert "curl -X POST" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "multipart POST" in res.note   # explicitly says it was NOT sent

    def test_sap_confirmed_severity_is_high_never_critical(self):
        # Reachability without the (refused) upload/RCE is HIGH, never critical.
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="sap", confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="sap", confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("sap", confirmed) == "high"
        assert HydraEngine._confirm_severity("sap_netweaver", confirmed) == "high"
        assert HydraEngine._confirm_severity("sap", pending) == "info"


# ═══════════════════════════════════════════════════
#  Astro CVE-2025-64525 — forwarded-origin middleware bypass
#  Benign X-Forwarded-* ACCESS-CONTROL status differential. HYDRA spoofs the
#  forwarded origin ONLY to an empty value or the target's OWN host — never a
#  foreign host a shared cache could replay — and reads status ONLY, never the
#  protected content.
# ═══════════════════════════════════════════════════
_ASTRO_FWD = ("x-forwarded-host", "x-forwarded-proto", "x-forwarded-port")


def _forwarded(headers) -> bool:
    """True if the request carried any X-Forwarded-* origin header. Keyed on
    PRESENCE, not truthiness — the empty-host spoof set ``{"x-forwarded-host":""}``
    is still 'present' even though ``.get()`` on it is falsy."""
    return any(k in headers for k in _ASTRO_FWD)


class TestAstroConfirm:
    TARGET = "https://t.tld/dashboard"

    def test_gated_403_flips_on_forwarded_spoof_is_reproduced(self):
        # 403 without forwarded headers, 200 once the forwarded origin is spoofed,
        # and the deliberate repeats hold → REPRODUCED. Status only.
        def responder(url, headers):
            return (200, {}, "secret") if _forwarded(headers) else (403, {}, "no")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert res.technique == "CVE-2025-64525 Astro forwarded-origin bypass"
        assert "CVE-2025-64525" in res.summary and "reproduced on" in res.summary
        assert res.poc and "x-forwarded" in res.poc.lower()
        # baseline sent FIRST with no forwarded headers…
        assert fetch.calls[0] == (self.TARGET, {})
        assert not _forwarded(fetch.calls[0][1])
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels and "repeat" in labels

    def test_redirect_gated_baseline_flips(self):
        # A login redirect is also 'gated'; the spoof flipping it to 200 counts.
        def responder(url, headers):
            if _forwarded(headers):
                return (200, {}, "content")
            return (302, {"Location": "https://t.tld/login"}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
    def test_ungated_baseline_not_confirmed(self):
        # Already 200 unauthenticated → no gate to bypass.
        def responder(url, headers):
            return (200, {}, "public")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "not access-gated" in res.summary

    def test_gate_holds_against_spoof_not_confirmed(self):
        # Gate holds regardless of forwarded headers (patched / does not trust
        # X-Forwarded-*) → not confirmed, OBSERVED.
        def responder(url, headers):
            return (403, {}, "forbidden")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "flipped it to HTTP 200" in res.summary

    def test_baseline_failure_is_unverified(self):
        def responder(url, headers):
            return (0, {}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_single_observation_is_inferred(self):
        # Flips once then the gate re-holds on the repeats → INFERRED, not
        # REPRODUCED. Still confirmed=True (one clean flip observed).
        class _FlipOnce:
            def __init__(self):
                self.hits = 0
            def __call__(self, url, headers):
                if _forwarded(headers):
                    self.hits += 1
                    return (200, {}, "x") if self.hits == 1 else (403, {}, "")
                return (403, {}, "forbidden")
        engine, _ = _nextjs_engine(_FlipOnce())
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.INFERRED
        assert "single observation" in res.summary
    def test_own_host_spoof_only_never_foreign(self):
        # A middleware that trusts ONLY a forwarded host equal to its own host:
        # the empty/proto/port sets don't flip, the own-host set does. Assert every
        # forwarded-host value HYDRA transmitted is empty or the target's OWN host —
        # never a foreign host a shared cache could replay.
        own = "t.tld"
        def responder(url, headers):
            if headers.get("x-forwarded-host") == own:
                return (200, {}, "content")
            return (403, {}, "forbidden")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is True
        for _u, h in fetch.calls:
            if "x-forwarded-host" in h:
                assert h["x-forwarded-host"] in ("", own)

    def test_astro_never_needs_a_param(self):
        # An empty param is fine — astro is a header/status differential, no
        # injectable parameter is required.
        def responder(url, headers):
            return (200, {}, "x") if _forwarded(headers) else (401, {}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "astro"))
        assert res.confirmed is True

    def test_astro_probe_headers_never_exploitation_grade(self):
        # never-exploit invariant: every header name AND value that reached the
        # wire is benign under the denylist.
        def responder(url, headers):
            return (200, {}, "x") if _forwarded(headers) else (403, {}, "")
        engine, fetch = _nextjs_engine(responder)
        _run(engine.confirm(self.TARGET, "", "astro"))
        assert len(fetch.calls) > 1
        for _u, hdrs in fetch.calls:
            for name, value in hdrs.items():
                assert is_exploitation_payload(name) is False
                assert is_exploitation_payload(value) is False

    def test_astro_severity_is_high_when_confirmed_else_info(self):
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="astro", confirmed=True,
            evidence_level=EvidenceLevel.REPRODUCED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="astro", confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("astro", confirmed) == "high"
        assert HydraEngine._confirm_severity("astro", pending) == "info"


# ═══════════════════════════════════════════════════
#  Next.js CVE-2025-57822 — request-header REFLECTION (SSRF precondition)
#  A benign unique marker header echoed back is a LEAD only: confirmed=False @
#  INFERRED. The real SSRF proof stays the operator-owned OOB callback path; the
#  confirmer NEVER fetches an internal/metadata host to 'prove' it.
# ═══════════════════════════════════════════════════
class TestHeaderReflection:
    TARGET = "https://t.tld/"
    NONCE = "deadbeefcafe"
    MARKER = "hydraprobedeadbeefcafe"

    def test_reflected_in_body_is_inferred_lead(self):
        def responder(url, headers):
            echo = headers.get(_HDR_REFLECT_NAME, "")
            return (200, {}, f"<p>hello {echo}</p>")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.INFERRED
        assert res.vuln_class == "nextjs_ssrf"
        assert res.technique == (
            "CVE-2025-57822 request-header reflection (SSRF precondition)")
        assert "reflected into response body" in res.summary
        assert self.MARKER in res.summary
        assert "oob-callback" in res.note
        # baseline sent first WITHOUT the marker header…
        assert fetch.calls[0] == (self.TARGET, {})
        # …then the exact benign marker header actually reached the wire.
        sent = [h.get(_HDR_REFLECT_NAME) for _u, h in fetch.calls
                if h.get(_HDR_REFLECT_NAME)]
        assert sent and all(v == self.MARKER for v in sent)

    def test_reflected_in_response_header(self):
        def responder(url, headers):
            m = headers.get(_HDR_REFLECT_NAME)
            return (200, {"X-Echo": m}, "body") if m else (200, {}, "body")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.INFERRED
        assert "a response header" in res.summary

    def test_not_reflected_is_observed(self):
        def responder(url, headers):
            return (200, {}, "static page, no echo")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "not reflected" in res.summary

    def test_marker_collision_is_unverified(self):
        # The unique marker already appears in the header-less control → any later
        # 'reflection' is coincidental, so bail honestly as UNVERIFIED.
        def responder(url, headers):
            return (200, {}, f"debug token {self.MARKER} present")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "collided" in res.summary

    def test_baseline_failure_is_unverified(self):
        def responder(url, headers):
            return (0, {}, "")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_aliases_dispatch_to_reflection(self):
        def responder(url, headers):
            echo = headers.get(_HDR_REFLECT_NAME, "")
            return (200, {}, f"x{echo}")
        for alias in ("next_ssrf", "header_reflection"):
            engine, _ = _nextjs_engine(responder)
            res = _run(engine.confirm(self.TARGET, "", alias, nonce=self.NONCE))
            assert res.vuln_class == "nextjs_ssrf"
            assert res.evidence_level == EvidenceLevel.INFERRED
            assert res.confirmed is False

    def test_reflection_never_needs_a_param(self):
        def responder(url, headers):
            echo = headers.get(_HDR_REFLECT_NAME, "")
            return (200, {}, f"x{echo}")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.evidence_level == EvidenceLevel.INFERRED

    def test_marker_is_alnum_and_benign(self):
        # The marker is pure alphanumeric so it passes every safety gate and can
        # never itself be an exploitation payload.
        assert self.MARKER.isalnum()
        assert is_exploitation_payload(self.MARKER) is False
        assert is_exploitation_payload(_HDR_REFLECT_NAME) is False

    def test_never_fetches_foreign_or_metadata_host(self):
        # Belt-and-braces: the confirmer only ever GETs the target itself — it
        # never reaches an internal/metadata host to 'prove' SSRF — and every
        # transmitted header is benign on name and value.
        def responder(url, headers):
            echo = headers.get(_HDR_REFLECT_NAME, "")
            return (200, {}, f"x{echo}")
        engine, fetch = _nextjs_engine(responder)
        _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert len(fetch.calls) > 1
        for url, hdrs in fetch.calls:
            assert url == self.TARGET
            assert "169.254.169.254" not in url and "metadata" not in url
            for name, value in hdrs.items():
                assert is_exploitation_payload(name) is False
                assert is_exploitation_payload(value) is False

    def test_reflection_severity_is_info_live_medium_only_if_confirmed(self):
        from hydra.main import HydraEngine
        # The live reflection result is ALWAYS confirmed=False → "info".
        def responder(url, headers):
            echo = headers.get(_HDR_REFLECT_NAME, "")
            return (200, {}, f"x{echo}")
        engine, _ = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "nextjs_ssrf", nonce=self.NONCE))
        assert res.confirmed is False
        assert HydraEngine._confirm_severity("nextjs_ssrf", res) == "info"
        # the "medium" tier is only reachable if a result were ever confirmed.
        forced = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="nextjs_ssrf",
            confirmed=True, evidence_level=EvidenceLevel.INFERRED)
        assert HydraEngine._confirm_severity("nextjs_ssrf", forced) == "medium"
        assert HydraEngine._confirm_severity("next_ssrf", forced) == "medium"
        assert HydraEngine._confirm_severity("header_reflection", forced) == "medium"


# ═══════════════════════════════════════════════════
#  Vite CVE-2025-30208 — server.fs.deny bypass PRESENCE
#  A pure STATUS differential on a guaranteed-NONEXISTENT, nonce'd canary that
#  matches a default deny pattern: (0) a normal non-denied path proves the
#  not-found status and rules out a blanket-403 server; (1) the denied canary
#  must be 403 (deny active); (2) the SAME canary + a benign trailing-separator
#  query suffix flips AWAY from 403 (loader reached for a file that does not
#  exist) → the deny check was skipped. Reads ZERO file content, uses NO ../
#  traversal / file:// / /@fs/. Presence is static → caps at OBSERVED.
# ═══════════════════════════════════════════════════
def _vite_engine(responder, scope=None, repeats=2):
    """Vite is a GET-only presence differential, so the header-free RecordingFetch
    is the right fake. Returns (engine, fetch) so a test can read fetch.urls."""
    fetch = RecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestViteConfirm:
    TARGET = "https://vite.t.tld/"
    NONCE = "deadbeefcafe"

    @staticmethod
    def _responder(normal=(404, {}, ""), deny=(403, {}, ""), bypass=(404, {}, "")):
        """Classify by URL shape. Order matters: the bypass URL is the canary
        PLUS a ``?raw??``/``?import&raw??`` suffix, so it also contains the canary
        substring — check the suffix marker FIRST."""
        def responder(url):
            if "raw" in url or "import" in url:        # denied canary + bypass suffix
                return bypass
            if url.split("?", 1)[0].endswith(".txt"):  # the normal non-denied control
                return normal
            return deny                                # a denied canary
        return responder

    def test_bypass_flip_is_confirmed_observed(self):
        # Denied canary is 403 but the SAME canary + a benign suffix flips to 404
        # (the loader was reached for a nonexistent file) → the deny check was
        # skipped → the bypass is PRESENT. Presence is static → OBSERVED, never
        # REPRODUCED, and no file content is ever read.
        engine, fetch = _vite_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED   # never REPRODUCED
        assert res.evidence_level != EvidenceLevel.REPRODUCED
        assert res.vuln_class == "vite"
        assert res.technique == "CVE-2025-30208 Vite server.fs.deny bypass"
        assert "server.fs.deny bypass present" in res.summary
        assert "CVE-2025-30208" in res.summary
        assert "no file content was read" in res.summary
        # control sent FIRST (the normal non-denied .txt path), then the payloads.
        assert fetch.urls[0].endswith(".txt")
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels
        assert labels.count("repeat") == 2                    # self.repeats
        assert res.poc

    def test_no_bypass_deny_holds_is_observed_not_confirmed(self):
        # Deny filter is active (403) AND the suffix does NOT skip it (still 403)
        # → not vulnerable / patched. Observed, but confirmed=False.
        engine, _ = _vite_engine(
            self._responder(normal=(404, {}, ""), deny=(403, {}, ""),
                            bypass=(403, {}, "")))
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "No server.fs.deny bypass observed" in res.summary

    def test_blanket_403_carries_no_signal_is_observed(self):
        # A server that answers 403 to a normal non-denied path 403s
        # indiscriminately, so a canary 403 means nothing → bail honestly.
        engine, _ = _vite_engine(self._responder(normal=(403, {}, "")))
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "403s indiscriminately" in res.summary

    def test_baseline_failure_is_unverified(self):
        # No usable baseline response (status 0 / transport error) → cannot
        # assess the differential → UNVERIFIED, not a false "not vulnerable".
        engine, _ = _vite_engine(self._responder(normal=(0, {}, "")))
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_vite_never_needs_a_param(self):
        # Presence is a fixed-endpoint property, so confirm() must not require a
        # ``param`` for the vite class (like sap/nextjs, unlike sqli).
        engine, _ = _vite_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is True

    def test_never_exploit_invariant(self):
        # Every send is a benign GET on a nonce'd, nonexistent canary: no send is
        # an exploitation payload and NONE uses ../ traversal, file://, or /@fs/.
        engine, fetch = _vite_engine(self._responder())
        _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert len(fetch.urls) > 1
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url
            assert "../" not in url and "..\\" not in url
            assert "file://" not in url and "/@fs/" not in url
        # the canary is nonce'd on every non-control send (never a real filename).
        for url in fetch.urls:
            if not url.endswith(".txt"):
                assert self.NONCE in url, url

    def test_reads_no_file_content_note(self):
        # The note must state, in plain terms, that HYDRA read ZERO file content
        # and used none of the traversal/file-scheme primitives.
        engine, res_fetch = _vite_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert "ZERO file content" in res.note
        assert "../" in res.note and "file://" in res.note and "/@fs/" in res.note
        # the PoC is GET-only: no POST / body-carrying curl flags.
        assert "curl -X POST" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc

    def test_deny_filter_not_active_is_observed_not_confirmed(self):
        # The canary is not 403 at all (no deny filter to bypass) → nothing to
        # prove; fall through both canaries to the honest "no bypass" result.
        engine, _ = _vite_engine(
            self._responder(normal=(404, {}, ""), deny=(404, {}, "")))
        res = _run(engine.confirm(self.TARGET, "", "vite", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "No server.fs.deny bypass observed" in res.summary

    def test_vite_confirmed_severity_is_high_never_critical(self):
        # A present-bypass PRESENCE finding (without the refused file read) is
        # HIGH, never critical; an unconfirmed result is info.
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="vite", confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="vite", confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("vite", confirmed) == "high"
        assert HydraEngine._confirm_severity("vite", pending) == "info"

    def test_canary_and_suffix_constants_are_benign(self):
        # The deny canaries match Vite's DEFAULT server.fs.deny patterns
        # (.env.* and *.pem) yet, once nonce'd, name no real file — and neither
        # they nor the query-only bypass suffixes are ever exploitation payloads.
        assert _VITE_DENY_CANARIES == (".env.{nonce}", "{nonce}.pem")
        for tmpl in _VITE_DENY_CANARIES:
            name = tmpl.format(nonce=self.NONCE)
            assert name.startswith(".env.") or name.endswith(".pem")
            assert is_exploitation_payload(name) is False
            assert ".." not in name and "/" not in name
        for suffix in _VITE_BYPASS_SUFFIXES:
            assert suffix.startswith("?") and "raw" in suffix
            assert is_exploitation_payload(suffix) is False
            assert ".." not in suffix and "file://" not in suffix


# ═══════════════════════════════════════════════════
#  Next.js Image Optimization cache-key confusion (CVE-2025-57752)
#  A benign cache-STATE differential: per fresh-nonce round, request A (Accept #1)
#  populates a key UNIQUE to the operator (the nonce lives INSIDE the inner url=,
#  which the optimizer keys on), then request B — SAME key, a DIFFERENT negotiated
#  Accept, first-ever send — is checked for a cache HIT read from the target's OWN
#  cache-status headers. A HIT proves the Accept header is confused OUT of the key
#  (mis-keying PRESENT). GET-only, reads a benign image, touches ZERO other-user
#  content; presence is a static config property → caps at OBSERVED, never
#  demonstrates cross-user poisoning. Header-aware fake so the two Accept values
#  actually reach the (stateful) cache responder.
# ═══════════════════════════════════════════════════
def _web_cache_engine(responder, scope=None, repeats=2):
    """web_cache sends a benign Accept-header differential, so the header-aware
    HeaderRecordingFetch is the right fake (2 positional args → SafeProber hands
    it the sanitized headers). Returns (engine, fetch) so a test can read
    fetch.calls as [(url, headers_dict), ...]."""
    fetch = HeaderRecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestWebCacheConfirm:
    TARGET = "https://img.t.tld/"
    NONCE = "deadbeefcafe"
    _IMG = ("image/avif", {"content-type": "image/avif", "etag": '"a1"'}, "AVIF")
    _PNG = ("image/png", {"content-type": "image/png", "etag": '"p9"'}, "PNG")

    @staticmethod
    def _stateful(keyed_on_accept, cache_headers=True):
        """A stateful optimizer cache. ``keyed_on_accept=False`` models the
        VULNERABLE server (Accept omitted from the key, so B hits A's entry);
        ``True`` models the PATCHED server (Accept in the key → B misses). First
        send of a key → MISS, any later send of the SAME key → HIT. When
        ``cache_headers`` is False no cache-state header is ever exposed."""
        store = {}

        def responder(url, headers):
            accept = headers.get(_IMG_VARY_HEADER, "")
            key = (url, accept) if keyed_on_accept else url
            hit = key in store
            store[key] = True
            ctype = "image/avif" if "avif" in accept else "image/png"
            hdrs = {"content-type": ctype, "etag": '"obj"'}
            if cache_headers:
                hdrs["x-vercel-cache"] = "HIT" if hit else "MISS"
            return (200, hdrs, "img-bytes")
        return responder

    def test_miskeying_present_is_confirmed_observed(self):
        # Vulnerable: Accept is NOT in the key, so B (a different Accept, same
        # nonce'd key, first-ever send) is served A's cached response → a HIT →
        # mis-keying PRESENT. Presence is static → OBSERVED, never REPRODUCED.
        engine, fetch = _web_cache_engine(self._stateful(keyed_on_accept=False))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert res.evidence_level != EvidenceLevel.REPRODUCED
        assert res.vuln_class == "web_cache"
        assert "cache-key confusion present" in res.summary
        assert "CVE-2025-57752" in res.summary
        assert res.target.endswith(_NEXT_IMAGE_PATH)
        # control (Accept #1 populate) sent before the payload (Accept #2) each round
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels
        assert res.poc

    def test_accept_in_key_is_not_confirmed(self):
        # Patched: Accept participates in the key, so B misses on every isolated
        # round → honestly NOT vulnerable, OBSERVED, confirmed=False.
        engine, _ = _web_cache_engine(self._stateful(keyed_on_accept=True))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "participates in the optimizer cache key" in res.summary

    def test_no_cache_header_is_undetermined(self):
        # 200s but the server exposes NO cache-state header (no Age / X-*-Cache),
        # so a HIT can't be told from a MISS → honestly undetermined.
        engine, _ = _web_cache_engine(
            self._stateful(keyed_on_accept=False, cache_headers=False))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "No cache-status signal was exposed" in res.summary

    def test_no_cacheable_image_bails_honestly(self):
        # No benign local raster image returns 200 → cannot obtain an optimized
        # image to test the cache key; bail without a false negative.
        engine, _ = _web_cache_engine(lambda url, headers: (404, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is False
        assert "Could not obtain a cacheable optimized image" in res.summary

    def test_populate_already_hit_is_inconclusive(self):
        # If the populate (A) request is ITSELF already a cache HIT, a coarse
        # upstream cache shares the key with others → a B HIT can't be attributed
        # to the Accept header; every round is skipped as un-isolatable.
        def responder(url, headers):
            return (200, {"content-type": "image/avif",
                          "x-vercel-cache": "HIT"}, "img")
        engine, _ = _web_cache_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is False
        assert "operator-isolated" in res.summary

    def test_web_cache_never_needs_a_param(self):
        # Presence is a fixed-endpoint property, so confirm() must not require a
        # ``param`` for the web_cache class (like vite/sap, unlike sqli).
        engine, _ = _web_cache_engine(self._stateful(keyed_on_accept=False))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is True

    def test_never_exploit_invariant(self):
        # Every send is a benign GET: no URL is exploitation-grade, none uses
        # ../ traversal or file://, and the nonce isolates every cache key. The
        # two Accept header values must ALSO pass the never-exploit header gate —
        # this is the regression lock on the `/*`-in-`*/*` refusal bug.
        engine, fetch = _web_cache_engine(self._stateful(keyed_on_accept=False))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert res.confirmed is True            # proves B was actually sent, not refused
        assert len(fetch.calls) > 1
        for url, hdrs in fetch.calls:
            assert is_exploitation_payload(url) is False, url
            assert "../" not in url and "..\\" not in url
            assert "file://" not in url
            assert self.NONCE in url, url        # operator-isolated key on every send
            for name, value in hdrs.items():
                assert is_safe_probe_header(name, value), (name, value)
        # both Accept values were seen on the wire (A populate + B differential)
        sent_accepts = {h.get(_IMG_VARY_HEADER, "") for _, h in fetch.calls}
        assert _IMG_ACCEPT_A in sent_accepts and _IMG_ACCEPT_B in sent_accepts

    def test_poc_is_get_only(self):
        # The reproduction is a two-GET cache-state differential — never a POST
        # or any body-carrying request (cache poisoning is NOT demonstrated).
        engine, _ = _web_cache_engine(self._stateful(keyed_on_accept=False))
        res = _run(engine.confirm(self.TARGET, "", "web_cache", nonce=self.NONCE))
        assert "curl -X POST" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        assert "PRECONDITION" in res.note and "zero other-user content" in res.note

    def test_web_cache_confirmed_severity_is_medium_never_critical(self):
        # A present-mis-keying PRECONDITION finding is MEDIUM, never critical
        # (no cross-user poisoning is demonstrated); unconfirmed stays info.
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="web_cache", confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="web_cache", confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("web_cache", confirmed) == "medium"
        assert HydraEngine._confirm_severity("web_cache", pending) == "info"

    def test_accept_constants_are_benign_and_wildcard_free(self):
        # Regression guard: the two Accept values must negotiate DIFFERENT formats
        # yet carry NO EXPLOITATION_MARKER. In particular they must not contain the
        # `*/*` media range — its `/*` substring is a SQL-inline-comment marker, so
        # a literal `*/*` would be refused fail-closed by the header gate and the
        # probe could never send. Keep them wildcard-free.
        assert _IMG_ACCEPT_A != _IMG_ACCEPT_B
        for v in (_IMG_ACCEPT_A, _IMG_ACCEPT_B):
            assert "/*" not in v and "*/" not in v, v
            assert is_exploitation_payload(v) is False, v
            assert is_safe_probe_header(_IMG_VARY_HEADER, v) is True, v


# ═══════════════════════════════════════════════════
#  CVE-2025-43865 — React Router / Remix prerender-data spoofing
#  (benign: a client-supplied-header → HTML reflection differential)
# ═══════════════════════════════════════════════════
def _react_router_engine(responder, scope=None, repeats=2):
    """react_router injects a benign ``X-React-Router-Prerender-Data`` header and
    looks for its pure-alnum marker reflected into the server HTML, so the
    header-aware HeaderRecordingFetch is the right fake (2 positional args →
    SafeProber hands it the sanitized headers). Returns (engine, fetch) so a test
    can read fetch.calls as [(url, headers_dict), ...]."""
    fetch = HeaderRecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestReactRouterConfirm:
    TARGET = "https://rr.t.tld/"
    NONCE = "deadbeefcafe"
    MARKER = "hydrardspoof" + NONCE

    @staticmethod
    def _vuln_body(url, headers):
        """Vulnerable server: serialises the client-supplied prerender ``data``
        into the server-rendered HTML (so the marker lands in the body)."""
        val = headers.get(_RR_PRERENDER_HEADER, "")
        body = "<html><body>app"
        if val:
            body += f"<script>window.__reactRouterContext={val}</script>"
        body += "</body></html>"
        return (200, {"content-type": "text/html"}, body)

    @staticmethod
    def _vuln_header(url, headers):
        """Variant: the server echoes the client prerender data into a RESPONSE
        header rather than the HTML body — still a reflection of our marker."""
        val = headers.get(_RR_PRERENDER_HEADER, "")
        hdrs = {"content-type": "text/html"}
        if val:
            hdrs["x-prerender-echo"] = val
        return (200, hdrs, "<html><body>app</body></html>")

    @staticmethod
    def _patched(url, headers):
        """Patched server: ignores the client prerender header entirely."""
        return (200, {"content-type": "text/html"}, "<html><body>app</body></html>")

    def test_reflected_in_body_is_confirmed_reproduced(self):
        # The marker lands in the HTML only when the header is sent, and holds on
        # every repeat → a genuine controlled spoofing differential → REPRODUCED.
        engine, _ = _react_router_engine(self._vuln_body)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert res.vuln_class == "react_router"
        assert self.MARKER in res.summary
        assert "CVE-2025-43865" in res.summary
        assert "prerender-data spoofing precondition is present" in res.summary
        labels = [e.label for e in res.exchanges]
        assert "control" in labels and "payload" in labels and "repeat" in labels
        assert res.poc

    def test_reflected_in_response_header_is_confirmed(self):
        # Reflection via a response header counts too (self._in_headers path).
        engine, _ = _react_router_engine(self._vuln_header)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert self.MARKER in res.summary

    def test_not_reflected_is_not_confirmed_observed(self):
        # Patched server never reflects the client header → honestly NOT present.
        engine, _ = _react_router_engine(self._patched)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "NOT reflected" in res.summary

    def test_marker_collision_is_undetermined(self):
        # If the UNIQUE marker already appears in the header-less control, any
        # later 'reflection' is coincidental → bail honestly as UNVERIFIED.
        def collide(url, headers):
            return (200, {}, f"<html>{self.MARKER} baked in</html>")
        engine, _ = _react_router_engine(collide)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "collided" in res.summary

    def test_baseline_failure_is_undetermined(self):
        # Baseline request fails (status 0) → cannot assess; no false negative.
        engine, _ = _react_router_engine(lambda url, headers: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_remix_alias_dispatches(self):
        # The 'remix' class alias routes to the same confirmer as react_router.
        engine, _ = _react_router_engine(self._vuln_body)
        res = _run(engine.confirm(self.TARGET, "", "remix", nonce=self.NONCE))
        assert res.confirmed is True
        assert res.vuln_class == "react_router"

    def test_react_router_never_needs_a_param(self):
        # The channel is a fixed-endpoint property, so confirm() must not require
        # a ``param`` for the react_router class (like vite/web_cache, unlike sqli).
        engine, _ = _react_router_engine(self._vuln_body)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is True

    def test_control_is_sent_header_less_first(self):
        # The baseline control must be the FIRST send and carry NO headers, so the
        # differential is attributable solely to the injected prerender header.
        engine, fetch = _react_router_engine(self._vuln_body)
        _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert fetch.calls[0] == (self.TARGET, {})
        # the injected header carried exactly the benign JSON prerender value
        value = '{"%s":{"data":"%s"}}' % (_RR_ROUTE_IDS[0], self.MARKER)
        sent = [h.get(_RR_PRERENDER_HEADER, "") for _, h in fetch.calls]
        assert value in sent

    def test_marker_is_alnum_and_benign(self):
        # The reflected marker is pure [A-Za-z0-9] — no HTML metacharacter — so it
        # can NEVER demonstrate executable XSS; the proof is the channel only.
        assert self.MARKER.isalnum()
        assert is_exploitation_payload(self.MARKER) is False

    def test_never_exploit_invariant(self):
        # Every send is a benign GET: no URL is exploitation-grade, none uses ../
        # traversal or file://. The injected JSON prerender header value must ALSO
        # pass the never-exploit header gate — a confirmed=True result proves the
        # payload was actually transmitted, not refused fail-closed.
        engine, fetch = _react_router_engine(self._vuln_body)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert res.confirmed is True            # proves the header was sent, not refused
        assert len(fetch.calls) > 1
        saw_header = False
        for url, hdrs in fetch.calls:
            assert is_exploitation_payload(url) is False, url
            assert "../" not in url and "..\\" not in url
            assert "file://" not in url
            for name, value in hdrs.items():
                assert is_safe_probe_header(name, value), (name, value)
                assert is_exploitation_payload(value) is False, value
                if name == _RR_PRERENDER_HEADER:
                    saw_header = True
                    assert self.MARKER in value
        assert saw_header                        # the prerender header reached the wire

    def test_poc_is_get_only(self):
        # The reproduction is a two-GET header-reflection differential — never a
        # POST or any body-carrying request (no XSS/poisoning is demonstrated).
        engine, _ = _react_router_engine(self._vuln_body)
        res = _run(engine.confirm(self.TARGET, "", "react_router", nonce=self.NONCE))
        assert "curl -X POST" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        assert "UNdemonstrated" in res.note

    def test_react_router_confirmed_severity_is_medium_never_critical(self):
        # A present-spoofing-channel finding is MEDIUM, never critical (no XSS or
        # cross-user poisoning is demonstrated); unconfirmed stays info.
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="react_router",
            confirmed=True, evidence_level=EvidenceLevel.REPRODUCED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="react_router",
            confirmed=False, evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("react_router", confirmed) == "medium"
        assert HydraEngine._confirm_severity("react_router", pending) == "info"
        assert HydraEngine._confirm_severity("remix", confirmed) == "medium"


# ═══════════════════════════════════════════════════
#  P13 — IngressNightmare CVE-2025-1974: admission-controller EXPOSURE
#  (reachability / posture ONLY — the AdmissionReview POST is the RCE and is
#  NEVER sent; a bare /healthz 200 is gated behind an admission signature)
# ═══════════════════════════════════════════════════
def _k8s_engine(responder, scope=None, repeats=2):
    """IngressNightmare exposure is a GET-only reachability/posture check, so the
    header-free RecordingFetch is the right fake. Returns (engine, fetch)."""
    fetch = RecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestK8sAdmissionConfirm:
    TARGET = "https://k8s.t.tld:8443"
    NONCE = "deadbeefcafe"

    @staticmethod
    def _route(healthz, webhook, control):
        """Responder keyed by path: the admission-webhook tuple when the webhook
        path is in the URL, else /healthz, else the control (random sibling)."""
        def responder(url):
            if _K8S_WEBHOOK_PATH in url:
                return webhook
            if _K8S_HEALTHZ_PATH in url:
                return healthz
            return control
        return responder

    def test_healthz_transport_failure_is_unverified(self):
        # No usable /healthz response (status 0 / transport error) → the service
        # may be firewalled / internal-only (the SAFE state); exposure cannot be
        # concluded → UNVERIFIED, never a false "not vulnerable".
        responder = self._route((0, {}, ""), (200, {}, ""), (404, {}, ""))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "firewalled" in res.summary

    def test_healthz_401_is_access_gated_not_confirmed(self):
        # 401 is exactly what a protected / in-cluster-only controller returns →
        # access control enforced, NOT the open unauthenticated exposure.
        responder = self._route((401, {}, "Unauthorized"),
                                (200, {}, ""), (404, {}, ""))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "access-gated" in res.summary

    def test_healthz_redirect_to_login_is_access_gated(self):
        # A 3xx to a login page is authentication enforced, not the exposure.
        responder = self._route(
            (302, {"Location": "https://k8s.t.tld/login"}, ""),
            (200, {}, ""), (404, {}, ""))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "access-gated" in res.summary

    def test_catchall_same_status_no_signature_not_confirmed(self):
        # /healthz 200 AND a random sibling also 200, with no admission signature
        # on either response → indistinguishable from a catch-all; not confirmed.
        responder = self._route((200, {}, "ok"), (200, {}, "ok"),
                                (200, {}, "ok"))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "catch-all" in res.summary

    def test_healthz_200_without_signature_not_confirmed(self):
        # A bare 200 /healthz is NOT admission-specific; without an ingress-nginx
        # signature HYDRA refuses to label it an exposed admission controller
        # (the control differs here, so this is not the catch-all branch).
        responder = self._route((200, {}, "ok"), (200, {}, "hello"),
                                (404, {}, "nope"))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "signature" in res.summary

    def test_healthz_200_webhook_rejects_get_405_confirmed(self):
        # /healthz answers 200 with no client cert and the webhook path rejects a
        # bare GET with 405 — the STRUCTURAL admission signature. Confirmed, and
        # reachability is static → OBSERVED (never REPRODUCED).
        responder = self._route((200, {}, "ok"),
                                (405, {}, "Method Not Allowed"),
                                (404, {}, "nope"))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert res.vuln_class == "k8s_admission"
        assert "webhook-rejects-GET:405" in res.summary
        assert "CVE-2025-1974" in res.summary
        assert "IngressNightmare" in res.note

    def test_healthz_200_webhook_banner_confirmed(self):
        # The webhook path answers a bare GET with the content-type error and an
        # AdmissionReview banner — the TEXTUAL signature. Confirmed, OBSERVED.
        responder = self._route(
            (200, {}, "ok"),
            (200, {}, "expected application/json for an AdmissionReview"),
            (404, {}, "nope"))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "admissionreview" in res.summary.lower()

    def test_fingerprint_reads_server_header(self):
        # The admission signature may come from a Server banner, not just a body.
        responder = self._route((200, {"Server": "ingress-nginx"}, ""),
                                (200, {}, "generic"), (404, {}, "nope"))
        engine, _ = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert "ingress-nginx" in res.summary

    def test_aliases_dispatch_to_k8s_admission(self):
        # Both the exposed_service and ingress_nightmare aliases route to the one
        # reachability confirmer and report the same vuln_class / technique.
        for alias in ("exposed_service", "ingress_nightmare"):
            responder = self._route((200, {}, "ok"), (405, {}, ""),
                                    (404, {}, ""))
            engine, _ = _k8s_engine(responder)
            res = _run(engine.confirm(self.TARGET, "", alias, nonce=self.NONCE))
            assert res.vuln_class == "k8s_admission"
            assert res.technique.startswith("CVE-2025-1974")
            assert res.confirmed is True

    def test_k8s_confirmed_severity_is_high_never_critical(self):
        # External exposure WITHOUT the (refused) AdmissionReview RCE is HIGH,
        # never critical; an unconfirmed posture result stays info.
        from hydra.main import HydraEngine
        confirmed = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="k8s_admission",
            confirmed=True, evidence_level=EvidenceLevel.OBSERVED)
        pending = ConfirmationResult(
            target=self.TARGET, param="", vuln_class="k8s_admission",
            confirmed=False, evidence_level=EvidenceLevel.OBSERVED)
        assert HydraEngine._confirm_severity("k8s_admission", confirmed) == "high"
        assert HydraEngine._confirm_severity("k8s_admission", pending) == "info"
        assert HydraEngine._confirm_severity("exposed_service", confirmed) == "high"

    def test_never_exploit_invariant_no_admission_post_ever(self):
        # The whole point: every send is a benign client-cert-less GET, none is
        # an exploitation payload or a traversal, and the AdmissionReview POST
        # (which IS the RCE) is NEVER emitted — not on the wire, not in the PoC.
        responder = self._route((200, {"Server": "ingress-nginx"}, "ok"),
                                (405, {}, "Method Not Allowed"),
                                (404, {}, "nope"))
        engine, fetch = _k8s_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "k8s_admission",
                                  nonce=self.NONCE))
        assert res.confirmed is True            # proves the GETs went through
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url
            assert "../" not in url and "..\\" not in url
        # exact GET order: control, /healthz, webhook, then 2 /healthz repeats
        assert len(fetch.urls) == 5
        assert fetch.urls[0].endswith("-hydra-nope")
        assert fetch.urls[1].endswith(_K8S_HEALTHZ_PATH)
        assert fetch.urls[2].endswith(_K8S_WEBHOOK_PATH)
        assert fetch.urls[3].endswith(_K8S_HEALTHZ_PATH)
        assert fetch.urls[4].endswith(_K8S_HEALTHZ_PATH)
        # the AdmissionReview POST is never a wire send nor a PoC command
        assert "-X POST" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        assert "never sends the AdmissionReview POST" in res.poc
        assert "did NOT send that POST" in res.note


# ═══════════════════════════════════════════════════
#  Static-JS / posture cluster — P19-P22
#  Each confirmer GETs the target's OWN HTML + its served <script src>
#  bundles, fingerprints a version, and pattern-matches a known-vulnerable
#  static source signature. The XSS / prototype-pollution / DOM-clobbering
#  payoff stays DETECT-ONLY: no payload is ever built or sent, no sink is
#  triggered, no message is posted. Findings cap at OBSERVED, never
#  REPRODUCED, never "critical". Fully offline (no socket).
# ═══════════════════════════════════════════════════
def _js_engine(responder, scope=None, repeats=2):
    """A static-JS confirmer only GETs the target's own HTML + its served
    ``<script src>`` bundles, so the header-free RecordingFetch is the right
    fake. Returns ``(engine, fetch)``."""
    fetch = RecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


def _site(html, bundles=None):
    """URL-keyed responder: serve a bundle body when its key is a substring of
    the requested URL, else serve the page ``html``. ``bundles`` maps a URL
    substring (e.g. ``"app.js"``) to a ``(status, headers, body)`` tuple."""
    bundles = bundles or {}

    def responder(url):
        for key, resp in bundles.items():
            if key in url:
                return resp
        return (200, {}, html)
    return responder


class TestSanitizerBypassConfirm:
    """P19 — CVE-2026-41238 DOMPurify prototype-pollution precondition.
    DETECT-ONLY: fingerprint a vulnerable DOMPurify build served by the target
    (version in [3.0.1, 3.4.0) + the CUSTOM_ELEMENT_HANDLING code path). Never
    pollutes Object.prototype, never sends a payload."""

    TARGET = "https://app.tld/"
    HTML = ('<!doctype html><html><head>'
            '<script src="/dompurify.js"></script>'
            '</head><body>hi</body></html>')

    def _vuln(self, body):
        return _site(self.HTML, {"dompurify.js": (200, {}, body)})

    def test_confirmed_vulnerable_build_with_fallback_literal(self):
        body = ("/*! @license DOMPurify 3.2.0 | (c) Cure53 */\n"
                "var DOMPurify=(function(){"
                "var cfg=CUSTOM_ELEMENT_HANDLING || {};return cfg;})();")
        engine, fetch = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "3.2.0" in res.summary
        assert "CUSTOM_ELEMENT_HANDLING" in res.summary
        assert "fallback literal is present" in res.summary
        assert "2026-41238" in res.technique
        labels = [e.label for e in res.exchanges]
        assert labels.count("control") == 1
        assert "fingerprint" in labels
        assert labels.count("repeat") == 2
        assert "payload" not in labels and "oob-callback" not in labels

    def test_confirmed_minified_build_without_literal(self):
        body = ("DOMPurify.version='3.1.0';"
                "var h=opts.CUSTOM_ELEMENT_HANDLING;"
                "DOMPurify.sanitize=function(s){return s;};")
        engine, _ = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "dompurify"))
        assert res.confirmed is True
        assert "3.1.0" in res.summary
        assert "Minified build" in res.summary

    def test_not_confirmed_patched_out_of_range(self):
        body = "/*! DOMPurify 3.4.0 */ var x=CUSTOM_ELEMENT_HANDLING || {};"
        engine, _ = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "patched" in res.summary

    def test_not_confirmed_in_range_but_no_signature(self):
        body = "/*! DOMPurify 3.2.0 */ var DOMPurify={sanitize:function(s){return s;}};"
        engine, _ = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is False
        assert "CUSTOM_ELEMENT_HANDLING code path was not found" in res.summary

    def test_not_confirmed_present_but_no_parseable_version(self):
        body = "window.DOMPurify=lib; var h=CUSTOM_ELEMENT_HANDLING;"
        engine, _ = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is False
        assert "no version" in res.summary

    def test_not_confirmed_no_dompurify_present(self):
        # neutral page/bundle so neither the markup nor the script URL mentions
        # the library — otherwise the "/dompurify.js" src itself trips the token.
        html = ('<!doctype html><html><head><script src="/app.js"></script>'
                '</head><body>x</body></html>')
        responder = _site(html, {"app.js": (200, {}, "var app=1;log('nope');")})
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "No DOMPurify" in res.summary

    def test_transport_failure_is_unverified(self):
        engine, _ = _js_engine(lambda url: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED

    def test_severity_is_high_never_critical(self):
        from hydra.main import HydraEngine
        for vc in ("sanitizer_bypass", "dompurify", "prototype_pollution"):
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            no = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=False)
            assert HydraEngine._confirm_severity(vc, ok) == "high"
            assert HydraEngine._confirm_severity(vc, no) == "info"

    def test_never_exploits(self):
        body = ("/*! DOMPurify 3.2.0 */ "
                "var c=CUSTOM_ELEMENT_HANDLING || {};")
        engine, fetch = _js_engine(self._vuln(body))
        res = _run(engine.confirm(self.TARGET, "", "sanitizer_bypass"))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False
            assert "../" not in _decode(url)
        assert all(e.label in ("control", "fingerprint", "repeat")
                   for e in res.exchanges)
        assert "never pollutes Object.prototype" in res.poc
        assert "-d " not in res.poc and "-X POST" not in res.poc

class TestPostMessageConfirm:
    """P20 — CVE-2025-5062 class: a served cross-document 'message' handler with
    no origin check reaching an innerHTML-family sink. DETECT-ONLY: HYDRA reads
    the listener source but never posts a message or triggers the sink."""

    TARGET = "https://shop.tld/"
    HTML = ('<!doctype html><html><head>'
            '<script src="/widget.js"></script>'
            '</head><body>shop</body></html>')
    VULN_JS = ('window.addEventListener("message", function(ev){'
               'var box=document.getElementById("out");'
               'box.innerHTML=ev.data.html;});')

    def _page(self, js, html=None):
        return _site(html or self.HTML, {"widget.js": (200, {}, js)})

    def test_confirmed_unguarded_listener_reaches_sink(self):
        engine, _ = _js_engine(self._page(self.VULN_JS))
        res = _run(engine.confirm(self.TARGET, "", "postmessage"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert ".innerHTML" in res.summary
        assert "2025-5062" in res.technique
        labels = [e.label for e in res.exchanges]
        assert labels.count("control") == 1 and "fingerprint" in labels
        assert labels.count("repeat") == 2

    def test_confirmed_fingerprints_woocommerce_generator(self):
        html = ('<!doctype html><html><head>'
                '<meta name="generator" content="WooCommerce 9.8.0">'
                '<script src="/widget.js"></script></head><body>x</body></html>')
        engine, _ = _js_engine(self._page(self.VULN_JS, html=html))
        res = _run(engine.confirm(self.TARGET, "", "postmessage_xss"))
        assert res.confirmed is True
        assert "WooCommerce 9.8.0" in res.summary

    def test_not_confirmed_origin_check_guards_listener(self):
        js = ('window.addEventListener("message", function(e){'
              'if (e.origin !== "https://trusted.tld") return;'
              'document.querySelector("#x").innerHTML=e.data;});')
        engine, _ = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "postmessage"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "origin check guards it" in res.summary

    def test_not_confirmed_no_message_handler(self):
        js = 'window.addEventListener("click", function(){el.innerHTML="safe";});'
        engine, _ = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "postmessage"))
        assert res.confirmed is False
        assert "No cross-document 'message' handler" in res.summary

    def test_transport_failure_is_unverified(self):
        engine, _ = _js_engine(lambda url: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "postmessage"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED

    def test_alias_dispatch(self):
        for vc in ("post_message", "postmessage_xss"):
            engine, _ = _js_engine(self._page(self.VULN_JS))
            res = _run(engine.confirm(self.TARGET, "", vc))
            assert res.confirmed is True
            assert ".innerHTML" in res.summary

    def test_severity_is_medium_never_critical(self):
        from hydra.main import HydraEngine
        for vc in ("postmessage", "post_message", "postmessage_xss"):
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            no = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=False)
            assert HydraEngine._confirm_severity(vc, ok) == "medium"
            assert HydraEngine._confirm_severity(vc, no) == "info"

    def test_never_exploits(self):
        engine, fetch = _js_engine(self._page(self.VULN_JS))
        res = _run(engine.confirm(self.TARGET, "", "postmessage"))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False
            assert "../" not in _decode(url)
        assert all(e.label in ("control", "fingerprint", "repeat")
                   for e in res.exchanges)
        assert "never calls win.postMessage" in res.poc
        assert "-d " not in res.poc and "-X POST" not in res.poc


class TestDomClobberingConfirm:
    """P21 — CVE-2025-1647 Bootstrap 3 [3.4.1, 4.0.0) tooltip/popover
    DOM-clobbering sanitizer. DETECT-ONLY: fingerprint the served version +
    the createHTMLDocument/sanitizeHtml sanitizer; never inject a clobbering
    element, never invoke the sanitizer."""

    TARGET = "https://site.tld/"
    HTML = ('<!doctype html><html><head>'
            '<script src="/bootstrap.js"></script>'
            '</head><body>site</body></html>')

    def _page(self, js):
        return _site(self.HTML, {"bootstrap.js": (200, {}, js)})

    def test_confirmed_vulnerable_bootstrap3(self):
        js = ("/*! Bootstrap v3.4.1 (https://getbootstrap.com/) */\n"
              "var Tooltip=function(){};Tooltip.VERSION='3.4.1';\n"
              "function sanitizeHtml(h){return document.implementation."
              "createHTMLDocument('').body;}")
        engine, _ = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "3.4.1" in res.summary
        assert "createHTMLDocument/sanitizeHtml" in res.summary
        assert "2025-1647" in res.technique

    def test_not_confirmed_out_of_range(self):
        js = ("/*! Bootstrap v4.1.3 */ createHTMLDocument sanitizeHtml")
        engine, _ = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        assert res.confirmed is False
        assert "outside the affected" in res.summary

    def test_not_confirmed_in_range_but_no_sanitizer(self):
        js = "/*! Bootstrap v3.4.1 */ var x=1;"
        engine, _ = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        assert res.confirmed is False
        assert "sanitizer was not found" in res.summary

    def test_not_confirmed_no_bootstrap(self):
        engine, _ = _js_engine(self._page("var jq=1;console.log('x');"))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        assert res.confirmed is False
        assert "No Bootstrap 3 build" in res.summary

    def test_transport_failure_is_unverified(self):
        engine, _ = _js_engine(lambda url: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        assert res.evidence_level == EvidenceLevel.UNVERIFIED

    def test_alias_dispatch_and_severity(self):
        from hydra.main import HydraEngine
        js = ("/*! Bootstrap v3.4.1 */ Tooltip.VERSION='3.4.1';"
              "createHTMLDocument sanitizeHtml")
        for vc in ("dom_clobber", "bootstrap"):
            engine, _ = _js_engine(self._page(js))
            res = _run(engine.confirm(self.TARGET, "", vc))
            assert res.confirmed is True
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            assert HydraEngine._confirm_severity(vc, ok) == "low"

    def test_never_exploits(self):
        js = ("/*! Bootstrap v3.4.1 */ Tooltip.VERSION='3.4.1';"
              "createHTMLDocument sanitizeHtml")
        engine, fetch = _js_engine(self._page(js))
        res = _run(engine.confirm(self.TARGET, "", "dom_clobbering"))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False
            assert "../" not in _decode(url)
        assert all(e.label in ("control", "fingerprint", "repeat")
                   for e in res.exchanges)
        assert "never injects a clobbering element" in res.poc
        assert "-d " not in res.poc and "-X POST" not in res.poc

class TestCspConfirm:
    """P22 — nonce-based CSP bypass PRECONDITIONS. PASSIVE: two plain GETs read
    only the CSP the target itself sends (header + <meta>). Flags meta-delivery,
    nonce reuse, or unsafe-inline alongside a nonce. Sends no bypass payload."""

    TARGET = "https://csp.tld/"

    def test_confirmed_nonce_reused_across_responses(self):
        def responder(url):
            return (200,
                    {"Content-Security-Policy": "script-src 'nonce-abc123' 'self'"},
                    "<html></html>")
        engine, fetch = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "csp"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "reused" in res.summary
        labels = [e.label for e in res.exchanges]
        assert labels == ["control", "repeat"]
        assert len(fetch.urls) == 2

    def test_confirmed_meta_delivered_nonce(self):
        body = ('<html><head><meta http-equiv="Content-Security-Policy" '
                "content=\"script-src 'nonce-xyz789'\"></head></html>")

        def responder(url):
            return (200, {}, body)
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "csp_nonce"))
        assert res.confirmed is True
        assert "meta http-equiv" in res.summary

    def test_confirmed_unsafe_inline_alongside_nonce(self):
        state = {"n": 0}

        def responder(url):
            state["n"] += 1
            return (200, {"Content-Security-Policy":
                          f"script-src 'nonce-k{state['n']}' 'unsafe-inline'"}, "")
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "csp_bypass"))
        assert res.confirmed is True
        assert "unsafe-inline" in res.summary

    def test_not_confirmed_fresh_nonce_well_configured(self):
        state = {"n": 0}

        def responder(url):
            state["n"] += 1
            return (200, {"Content-Security-Policy":
                          f"script-src 'nonce-f{state['n']}' 'self'"}, "")
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "csp"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "correctly configured" in res.summary

    def test_not_confirmed_no_csp_sent(self):
        engine, _ = _js_engine(lambda url: (200, {}, "<html></html>"))
        res = _run(engine.confirm(self.TARGET, "", "csp"))
        assert res.confirmed is False
        assert "No Content-Security-Policy sent" in res.summary

    def test_transport_failure_is_unverified(self):
        engine, _ = _js_engine(lambda url: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "csp"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "cannot read its CSP" in res.summary

    def test_severity_is_low_never_critical(self):
        from hydra.main import HydraEngine
        for vc in ("csp", "csp_bypass", "csp_nonce"):
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            no = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=False)
            assert HydraEngine._confirm_severity(vc, ok) == "low"
            assert HydraEngine._confirm_severity(vc, no) == "info"

    def test_never_exploits(self):
        def responder(url):
            return (200,
                    {"Content-Security-Policy": "script-src 'nonce-abc123'"},
                    "<html></html>")
        engine, fetch = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "csp"))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False
            assert url == self.TARGET
        assert all(e.label in ("control", "repeat") for e in res.exchanges)
        assert "injects no inline script" in res.poc
        assert "-d " not in res.poc and "-X POST" not in res.poc


# ═══════════════════════════════════════════════════
#  P2/P5 — authorized secret-overshare (KEY-presence, VALUE redacted)
# ═══════════════════════════════════════════════════
# A populated secret value ≥16 chars → a non-empty salted fingerprint, and one
# that deliberately contains `--` and `/*` so the OneLogin test proves an opaque
# operator token is forwarded VERBATIM (never corrupted by the exploitation gate).
_RMQ_SECRET = "r@bbit-oauth-client-secret-ABCDEFGH"   # len 35, populated, >=16
_OL_SECRET = "onelogin-oidc-client-secret-ZYXWVUT9"   # len 36, populated, >=16


def _assert_value_never_leaks(res, *secrets):
    """The whole point of P2/P5: the secret VALUE must never surface in any
    operator-facing field (summary / PoC / exchanges) or the serialized finding.
    Key NAMES and redacted paths are fine; the value itself is not."""
    import json as _json
    blob = (res.summary or "") + "\x00" + (res.poc or "")
    for e in res.exchanges:
        blob += "\x00" + str(e.label) + "\x00" + str(e.url) + "\x00" + str(e.note)
    blob += "\x00" + _json.dumps(res.as_dict())
    for s in secrets:
        assert s and s not in blob


class TestRabbitMqSecretConfirm:
    """P2 — CVE-2026-5721. UNAUTH GET of the RabbitMQ management OAuth config;
    flag that an ``oauth_client_secret`` KEY is present and REDACT the value.
    Never reads, echoes, stores, or reuses the secret itself."""

    TARGET = "https://rabbit.tld/"

    def test_confirmed_observed_then_reproduced_on_stable_repeat(self):
        # /api/auth overshares the OAuth client_secret to anonymous callers; a
        # deliberate repeat re-exposes the SAME key (matching fingerprint) → the
        # evidence honestly rises to REPRODUCED. The value is never read.
        body = ('{"oauth_provider":"keycloak","oauth_client_secret":"%s",'
                '"oauth_client_id":"rabbit-mgmt"}') % _RMQ_SECRET

        def responder(url):
            if "/api/auth" in url:
                return (200, {"Content-Type": "application/json"}, body)
            return (404, {}, "")
        engine, fetch = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "rabbitmq_oauth"))

        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert "CVE-2026-5721" in res.technique
        # the KEY name may appear; the VALUE never does
        assert "oauth_client_secret" in res.summary
        assert "[REDACTED]" in res.poc
        _assert_value_never_leaks(res, _RMQ_SECRET)
        # one control GET to /api/auth + the confirming repeat to the SAME url
        labels = [e.label for e in res.exchanges]
        assert labels == ["control", "repeat"]
        assert all("/api/auth" in u for u in fetch.urls)

    def test_observed_only_when_repeat_does_not_re_expose(self):
        # First GET leaks; the repeat returns a sanitized body (patched between
        # the two) → no stable re-exposure → stays OBSERVED, not REPRODUCED.
        state = {"n": 0}
        leak = '{"oauth_client_secret":"%s"}' % _RMQ_SECRET

        def responder(url):
            if "/api/auth" in url:
                state["n"] += 1
                return (200, {}, leak if state["n"] == 1 else '{"status":"ok"}')
            return (404, {}, "")
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "rabbitmq"))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        _assert_value_never_leaks(res, _RMQ_SECRET)

    def test_direct_endpoint_pointing_is_probed_first(self):
        # Operator may point --target straight at an endpoint; it is tried first.
        tgt = "https://rabbit.tld/api/definitions"
        body = '{"oauth_client_secret":"%s"}' % _RMQ_SECRET

        def responder(url):
            return (200, {}, body) if "/api/definitions" in url else (404, {}, "")
        engine, fetch = _js_engine(responder)
        res = _run(engine.confirm(tgt, "", "rabbitmq_secret"))
        assert res.confirmed is True
        assert fetch.urls[0] == tgt
        _assert_value_never_leaks(res, _RMQ_SECRET)

    def test_placeholder_value_is_not_a_finding(self):
        # The secret KEY is present but the value is an empty/placeholder string
        # → not a real exposure. No false positive, and nothing to redact.
        def responder(url):
            if "/api/auth" in url:
                return (200, {}, '{"oauth_client_secret":"","client_secret":"changeme"}')
            return (404, {}, "")
        engine, _ = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "rabbitmq_oauth"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "no populated secret-named keys" in res.summary \
            or "exposed no populated" in res.summary

    def test_unverified_when_unreachable(self):
        # Transport failure on every candidate → honestly UNVERIFIED.
        engine, _ = _js_engine(lambda url: (0, {}, ""))
        res = _run(engine.confirm(self.TARGET, "", "rabbitmq_oauth"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "did not return a readable response" in res.summary

    def test_never_exploits_only_benign_get(self):
        body = '{"oauth_client_secret":"%s"}' % _RMQ_SECRET
        responder = lambda url: ((200, {}, body) if "/api/auth" in url
                                 else (404, {}, ""))
        engine, fetch = _js_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "rabbitmq_oauth"))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False
        # PoC is a single benign GET recipe — no body, no state-changing verb
        assert "curl -s" in res.poc
        assert "-d " not in res.poc and "-X POST" not in res.poc
        assert "never" in res.note.lower() and "pivot" in res.note.lower()

    def test_severity_high_when_confirmed_info_otherwise(self):
        from hydra.main import HydraEngine
        for vc in ("rabbitmq_oauth", "rabbitmq", "rabbitmq_secret"):
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            no = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=False)
            assert HydraEngine._confirm_severity(vc, ok) == "high"
            assert HydraEngine._confirm_severity(vc, no) == "info"


class TestOneLoginSecretConfirm:
    """P5 — CVE-2025-59363. AUTHENTICATED GET of the OneLogin apps API using the
    OPERATOR'S OWN in-scope token; flag that each app's ``client_secret`` KEY is
    present and REDACT the value. Never mints, reuses, or pivots with a secret."""

    TARGET = "https://one.tld/"
    # An operator token that contains `--` and `/*` on purpose — a legit opaque
    # bearer must be forwarded verbatim, not dropped by the exploitation gate.
    TOKEN_VALUE = "Bearer own-key--v2/*prod=="
    AUTH = "Authorization: " + TOKEN_VALUE

    def test_requires_operator_token_nothing_sent(self):
        # Without the operator's own credential HYDRA sends NOTHING and says so.
        engine, fetch = _nextjs_engine(lambda url, h: (200, {}, "{}"))
        res = _run(engine.confirm(self.TARGET, "", "onelogin_oidc"))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "needs the operator's OWN in-scope" in res.summary
        assert "Nothing was sent" in res.summary
        assert fetch.calls == []          # fail-closed: no request on the wire

    def test_confirmed_token_forwarded_verbatim_value_redacted(self):
        apps = ('[{"id":1,"name":"app","client_id":"pub-1",'
                '"client_secret":"%s"}]') % _OL_SECRET

        def responder(url, headers):
            if "/api/2/apps" in url and headers.get("Authorization"):
                return (200, {}, apps)
            return (401, {}, "unauthorized")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "onelogin_oidc",
                                  auth_header=self.AUTH))

        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.REPRODUCED
        assert "CVE-2025-59363" in res.technique
        assert "client_secret" in res.summary
        # the operator's OWN token reached the wire, forwarded byte-for-byte
        # (the `--` / `/*` substrings prove the exploitation gate did not touch it)
        sent = [h.get("Authorization") for _u, h in fetch.calls]
        assert sent and all(v == self.TOKEN_VALUE for v in sent)
        # neither the leaked app secret NOR the operator's token leaks anywhere
        _assert_value_never_leaks(res, _OL_SECRET, self.TOKEN_VALUE)
        # the PoC uses a placeholder, never the real token
        assert "<YOUR-OWN-IN-SCOPE-TOKEN>" in res.poc
        assert "Authorization" in res.poc

    def test_authed_but_no_overshare_not_confirmed(self):
        # Patched tenant: apps come back WITHOUT a secret key → not confirmed,
        # and the operator's token still reached the wire (we did authenticate).
        apps = '[{"id":1,"name":"app","client_id":"pub-1"}]'

        def responder(url, headers):
            if "/api/2/apps" in url and headers.get("Authorization"):
                return (200, {}, apps)
            return (401, {}, "")
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "onelogin",
                                  auth_header=self.AUTH))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert any(h.get("Authorization") == self.TOKEN_VALUE
                   for _u, h in fetch.calls)

    def test_unsafe_credential_header_is_refused_fail_closed(self):
        # A credential value carrying CR/LF would split the request → the probe
        # is refused BEFORE transmission; nothing reaches the responder.
        bad = "Authorization: Bearer good\r\nX-Injected: 1"
        engine, fetch = _nextjs_engine(lambda url, h: (200, {}, "{}"))
        res = _run(engine.confirm(self.TARGET, "", "onelogin_oidc",
                                  auth_header=bad))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert fetch.calls == []          # fail-closed, nothing transmitted

    def test_never_exploits_only_benign_get(self):
        apps = '[{"id":1,"client_secret":"%s"}]' % _OL_SECRET

        def responder(url, headers):
            return ((200, {}, apps) if "/api/2/apps" in url and
                    headers.get("Authorization") else (401, {}, ""))
        engine, fetch = _nextjs_engine(responder)
        res = _run(engine.confirm(self.TARGET, "", "onelogin_oidc",
                                  auth_header=self.AUTH))
        for url, _h in fetch.calls:
            assert is_exploitation_payload(url) is False
        assert "-d " not in res.poc and "-X POST" not in res.poc
        assert "pivot" in res.note.lower()

    def test_severity_high_when_confirmed_info_otherwise(self):
        from hydra.main import HydraEngine
        for vc in ("onelogin_oidc", "onelogin", "oidc_secret"):
            ok = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=True)
            no = ConfirmationResult(target=self.TARGET, param="", vuln_class=vc,
                                    confirmed=False)
            assert HydraEngine._confirm_severity(vc, ok) == "high"
            assert HydraEngine._confirm_severity(vc, no) == "info"


class TestSecretOvershareStrategies:
    """The breadth-pass registry must expose both P2/P5 classes as route/endpoint
    strategies: EMPTY parameter_targets (nothing auto-fuzzed), high severity."""

    def test_registry_entries_are_endpoint_only(self):
        from hydra.hunt.strategies import get_strategy
        for vc in ("rabbitmq_oauth", "rabbitmq", "rabbitmq_secret",
                   "onelogin_oidc", "onelogin", "oidc_secret"):
            s = get_strategy(vc)
            assert s is not None, vc
            assert s.parameter_targets == []        # never auto-sends a param
            assert s.severity_range == "high"
        assert "/api/auth" in get_strategy("rabbitmq_oauth").paths_to_check
        assert "/api/2/apps" in get_strategy("onelogin_oidc").paths_to_check


# ═══════════════════════════════════════════════════
#  PHP-CGI Best-Fit / WorstFit argument injection (CVE-2024-4577)
#  A benign Windows-locale look-alike differential: a plain GET of a PHP-CGI
#  endpoint should NOT print a php version banner, but the Unicode look-alike
#  '%AD' (U+00AD SOFT HYPHEN → Best-Fit '-') turns a query of ``?%ADv`` into the
#  php-cgi command-line flag ``-v`` (print version). If the banner now appears
#  (and did NOT in the control) the look-alike was folded onto the command line
#  → the argument-injection CHANNEL is PRESENT. HYDRA injects ONLY the read-only
#  -v/-V flag; it NEVER injects -d/-s/-r/-f/-i and NEVER sends the php://input
#  RCE body, so the finding is a precondition CHANNEL, caps at OBSERVED, and is
#  never 'critical'. GET-only presence differential → header-free RecordingFetch.
# ═══════════════════════════════════════════════════
def _worstfit_engine(responder, scope=None, repeats=2):
    """Returns (engine, fetch) so a test can read fetch.urls — control-first
    ordering and the exact (benign) flag ever injected onto the wire."""
    fetch = RecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


_PHP_BANNER = (
    "PHP 8.3.2 (cgi-fcgi) (built: Jan  1 2026 00:00:00)\n"
    "Copyright (c) The PHP Group\n"
    "Zend Engine v4.3.2, Copyright (c) Zend Technologies\n"
)


class TestWorstFitConfirm:
    TARGET = "https://php.t.tld/index.php"
    NONCE = "deadbeefcafe"

    @staticmethod
    def _responder(control=(200, {}, "<html>app home</html>"),
                   banner=(200, {}, _PHP_BANNER)):
        """Classify by URL shape. The look-alike probe carries ``%AD`` in its
        query; a plain control request never does. ``banner`` is what the
        look-alike surfaces (default: a php version banner → channel present);
        ``control`` is the plain-request body (default: ordinary app HTML)."""
        def responder(url):
            if "%ad" in url.lower():      # the ?%ADv / ?%ADV look-alike probe
                return banner
            return control                # plain control request
        return responder
    def test_lookalike_flip_is_confirmed_observed(self):
        # Control shows NO php banner, but ?%ADv surfaces one → the look-alike
        # was folded onto the php-cgi command line as -v. Presence of the
        # injection channel is static → OBSERVED, never REPRODUCED.
        engine, fetch = _worstfit_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert res.evidence_level != EvidenceLevel.REPRODUCED
        assert res.vuln_class == "best_fit_charset"
        assert "CVE-2024-4577" in res.technique
        assert "WorstFit" in res.technique and "argument injection" in res.technique
        assert "CVE-2024-4577" in res.summary and "WorstFit" in res.summary
        assert "no code was run" in res.summary
        # the control request is sent FIRST, carries no look-alike and no query.
        assert fetch.urls[0] == self.TARGET
        assert "%ad" not in fetch.urls[0].lower() and "?" not in fetch.urls[0]
        # labels: control, payload, then exactly `repeats` repeats.
        labels = [e.label for e in res.exchanges]
        assert labels[0] == "control"
        assert "payload" in labels
        assert labels.count("repeat") == 2
        assert res.poc  # a reproduction recipe is attached

    def test_preexisting_banner_is_differential_void(self):
        # The endpoint ALREADY prints a php version banner on a plain request, so
        # no injection can be inferred — the differential is void and skipped.
        engine, _ = _worstfit_engine(
            self._responder(control=(200, {}, _PHP_BANNER)))
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert ("No PHP-CGI Best-Fit argument-injection channel observed"
                in res.summary)
        assert any("differential" in e.note and "void" in e.note
                   for e in res.exchanges)
    def test_no_channel_is_observed_not_confirmed(self):
        # Control has no banner AND the look-alike never surfaces one → there is
        # no injection channel; honest OBSERVED-not-confirmed.
        engine, _ = _worstfit_engine(
            self._responder(banner=(200, {}, "<html>app home</html>")))
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert ("No PHP-CGI Best-Fit argument-injection channel observed"
                in res.summary)

    def test_baseline_failure_is_unverified(self):
        # Every control request fails (status 0) → the differential cannot be
        # assessed at all → UNVERIFIED, honestly.
        engine, _ = _worstfit_engine(
            self._responder(control=(0, {}, ""), banner=(0, {}, "")))
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline request failed" in res.summary

    def test_worstfit_never_needs_a_param(self):
        # Route/endpoint class: confirm works with an empty param (nothing is
        # ever auto-fuzzed into a query parameter).
        engine, _ = _worstfit_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.param == ""

    def test_never_exploit_invariant(self):
        # The never-exploit line: no sent URL is ever an exploitation payload,
        # and the ONLY flag ever injected is the read-only -v/-V (query == %ADv /
        # %ADV) — never -d/-s/-r/-f/-i, and the PoC is GET-only.
        engine, fetch = _worstfit_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "best_fit_charset",
                                  nonce=self.NONCE))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url
            if "?" in url:
                q = url.split("?", 1)[1]
                assert q.lower() == "%adv", url      # ONLY -v / -V, nothing else
                for bad in ("%add", "%ads", "%adr", "%adf", "%adi"):
                    assert bad not in url.lower(), url
        assert "curl -X POST" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        # the note names the refused RCE chain in plain terms.
        assert "php://input" in res.note and "-d" in res.note
    def test_worstfit_confirmed_severity_is_high_never_critical(self):
        # A present injection CHANNEL (not RCE) is HIGH, never critical; an
        # unconfirmed result is info. All four registered aliases map the same.
        from hydra.main import HydraEngine
        for vc in ("best_fit_charset", "worstfit", "php_cgi",
                   "php_cgi_argument_injection"):
            confirmed = ConfirmationResult(
                target=self.TARGET, param="", vuln_class=vc, confirmed=True,
                evidence_level=EvidenceLevel.OBSERVED)
            pending = ConfirmationResult(
                target=self.TARGET, param="", vuln_class=vc, confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED)
            assert HydraEngine._confirm_severity(vc, confirmed) == "high"
            assert HydraEngine._confirm_severity(vc, pending) == "info"

    def test_version_banner_matcher_is_specific(self):
        # The banner matcher fires ONLY on real php version-banner signatures,
        # never on ordinary application HTML (no false "channel present").
        assert ConfirmationEngine._php_version_banner("<html>welcome</html>") == ""
        assert ConfirmationEngine._php_version_banner("PHP 8.3.2 (cgi-fcgi)")
        assert ConfirmationEngine._php_version_banner("Zend Engine v4")

    def test_candidates_strip_query_and_dedupe(self):
        # A ``.php`` target is tested first with query/fragment stripped (so the
        # look-alike flag is the ONLY query segment), then the common Windows
        # php-cgi handler paths — all de-duplicated.
        cands = ConfirmationEngine._worstfit_candidates(
            "https://php.t.tld/index.php?x=1#frag")
        assert cands[0] == "https://php.t.tld/index.php"
        assert all("?" not in c and "#" not in c for c in cands)
        assert len(cands) == len(set(cands))
        for p in _WORSTFIT_PHP_PATHS:
            assert any(c.endswith(p) for c in cands)

    def test_worstfit_constants_are_benign(self):
        # The soft-hyphen octet and the version-flag allow-list are benign: the
        # allow-list is {v, V} ONLY, and no look-alike probe URL — on any
        # candidate path — is ever an exploitation payload.
        assert _WORSTFIT_SOFT_HYPHEN == "%AD"
        assert _WORSTFIT_FLAGS == ("v", "V")
        for flag in _WORSTFIT_FLAGS:
            assert flag not in ("d", "s", "r", "f", "i")   # never a dangerous flag
            assert is_exploitation_payload(
                f"{_WORSTFIT_SOFT_HYPHEN}{flag}") is False
        for p in _WORSTFIT_PHP_PATHS:
            assert p.startswith("/")
            for flag in _WORSTFIT_FLAGS:
                probe = f"https://php.t.tld{p}?{_WORSTFIT_SOFT_HYPHEN}{flag}"
                assert is_exploitation_payload(probe) is False


# ═══════════════════════════════════════════════════
#  CVE-2025-24813 — Apache Tomcat partial-PUT precondition (dangerous methods)
#
#  A bodyless, non-mutating OPTIONS (enabler #3) reads the capability-advertising
#  ``Allow`` response header. A PUT in the advertised set means the default
#  servlet accepts writes (``readonly=false``) — the structural PRECONDITION for
#  the partial-PUT upload + session-deserialization RCE chain. HYDRA observes PUT
#  only as *advertised*: it NEVER sends PUT/DELETE/PATCH, a partial-PUT
#  (Content-Range) upload, or the serialized-session gadget. Precondition, not
#  proof → caps at OBSERVED, severity medium, never 'critical'. The method-aware
#  3-arg fake exercises SafeProber's arity-3 dispatch and proves the verb on the
#  wire is OPTIONS (never GET/PUT).
# ═══════════════════════════════════════════════════
class MethodRecordingFetch:
    """Method-aware fetch: ``async fetch(url, headers=None, method="GET")``.

    Three positional args → ``SafeProber._fetch_arity()`` returns 3, so the verb
    HYDRA chose reaches the wire and is observable here (the whole point of the
    OPTIONS-only guarantee). Records every ``(url, method)`` pair; the responder
    is called ``responder(url, method)``.
    """

    def __init__(self, responder=None):
        self.calls = []  # list of (url, method)
        self._responder = responder or (lambda url, method: (200, {}, ""))

    async def __call__(self, url, headers=None, method="GET"):
        self.calls.append((url, method))
        return self._responder(url, method)

    @property
    def urls(self):
        return [u for u, _ in self.calls]

    @property
    def methods(self):
        return [m for _, m in self.calls]


def _dangerous_methods_engine(responder, scope=None, repeats=2):
    """Returns (engine, fetch) so a test can read fetch.methods — proving every
    verb on the wire is OPTIONS — and fetch.urls."""
    fetch = MethodRecordingFetch(responder)
    prober = SafeProber(scope_engine=scope, fetch=fetch)
    return ConfirmationEngine(prober=prober, repeats=repeats), fetch


class TestDangerousHttpMethodsConfirm:
    TARGET = "https://tc.t.tld/manager/"
    ROOT = "https://tc.t.tld/"
    NONCE = "deadbeefcafe"

    @staticmethod
    def _responder(allow="GET, HEAD, POST, PUT, OPTIONS",
                   server="Apache-Coyote/1.1", status=200):
        """Build responder(url, method). Every OPTIONS answers with an ``Allow``
        header; ``allow`` defaults to a set that INCLUDES PUT (precondition
        present) and ``server`` to a Tomcat/Coyote banner. status=0 simulates a
        dead endpoint; allow=None omits the Allow header entirely."""
        def responder(url, method):
            headers = {}
            if allow is not None:
                headers["Allow"] = allow
            if server:
                headers["Server"] = server
            return (status, headers, "")
        return responder

    def test_put_advertised_is_confirmed_observed(self):
        # OPTIONS Allow advertises PUT on a Tomcat/Coyote stack → the write-enabled
        # default-servlet precondition is present. Advertised capability is static
        # → OBSERVED, never REPRODUCED, never critical.
        engine, fetch = _dangerous_methods_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert res.evidence_level != EvidenceLevel.REPRODUCED
        assert res.vuln_class == "dangerous_http_methods"
        assert "CVE-2025-24813" in res.technique and "partial-PUT" in res.technique
        assert "CVE-2025-24813" in res.summary
        assert "PUT is advertised" in res.summary
        assert "identifies Tomcat/Coyote" in res.summary
        assert res.target == self.TARGET          # operator path tested first
        assert res.poc
        # EVERY verb on the wire is OPTIONS — never GET, never a write.
        assert set(fetch.methods) == {"OPTIONS"}
        # labels: a detection OPTIONS then exactly `repeats` stability repeats.
        labels = [e.label for e in res.exchanges]
        assert labels[0] == "options"
        assert labels.count("repeat") == 2

    def test_put_absent_is_observed_not_confirmed(self):
        # Allow lists only safe methods → no partial-PUT precondition; honest
        # OBSERVED-not-confirmed, not UNVERIFIED (the server did answer).
        engine, fetch = _dangerous_methods_engine(
            self._responder(allow="GET, HEAD, POST, OPTIONS"))
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "No dangerous write method advertised" in res.summary
        assert set(fetch.methods) == {"OPTIONS"}

    def test_baseline_failure_is_unverified(self):
        # Every OPTIONS fails (status 0) → the advertised method set cannot be
        # read at all → UNVERIFIED, honestly.
        engine, _ = _dangerous_methods_engine(
            self._responder(status=0, server=""))
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is False
        assert res.evidence_level == EvidenceLevel.UNVERIFIED
        assert "Baseline OPTIONS request failed" in res.summary

    def test_non_tomcat_banner_is_generic_precondition(self):
        # PUT advertised but the Server banner is NOT Tomcat/Coyote → still a
        # write-enabled precondition (confirmed), flagged as possibly-not the
        # specific Tomcat CVE.
        engine, _ = _dangerous_methods_engine(
            self._responder(server="nginx/1.25.3"))
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.evidence_level == EvidenceLevel.OBSERVED
        assert "not identifiably Tomcat/Coyote" in res.summary

    def test_missing_server_banner_still_confirms(self):
        # No Server header at all: PUT advertised is still the precondition.
        engine, _ = _dangerous_methods_engine(self._responder(server=""))
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert "not identifiably Tomcat/Coyote" in res.summary
        assert "(no Server banner advertised)" in res.poc

    def test_never_needs_a_param(self):
        # Route/capability class: confirm works with an empty param (nothing is
        # ever fuzzed into a query parameter — a bodyless OPTIONS carries nothing).
        engine, _ = _dangerous_methods_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert res.confirmed is True
        assert res.param == ""

    def test_stability_repeats_recorded(self):
        # With repeats=3 and PUT advertised on every OPTIONS, the summary records
        # the advertisement held across 4 OPTIONS requests (1 detection + 3).
        engine, fetch = _dangerous_methods_engine(self._responder(), repeats=3)
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        labels = [e.label for e in res.exchanges]
        assert labels.count("repeat") == 3
        assert "advertised on 4 OPTIONS requests" in res.summary
        assert set(fetch.methods) == {"OPTIONS"}

    def test_dispatch_aliases_route_to_confirmer(self):
        # All five registered aliases reach _confirm_dangerous_http_methods.
        for vc in ("dangerous_http_methods", "dangerous_methods",
                   "http_methods", "tomcat_partial_put", "partial_put"):
            engine, _ = _dangerous_methods_engine(self._responder())
            res = _run(engine.confirm(self.TARGET, "", vc, nonce=self.NONCE))
            assert res.confirmed is True, vc
            assert res.vuln_class == "dangerous_http_methods", vc

    def test_allow_header_parse_is_case_insensitive(self):
        # A lowercase 'allow' header name and lowercase method tokens still parse
        # — PUT is detected regardless of case.
        engine, _ = _dangerous_methods_engine(
            self._responder(allow=None, server=""))

        def responder(url, method):
            return (200, {"allow": "get, head, put, options"}, "")
        engine2, _ = _dangerous_methods_engine(responder)
        res = _run(engine2.confirm(self.TARGET, "", "dangerous_http_methods",
                                   nonce=self.NONCE))
        assert res.confirmed is True
        # the helper folds header-name AND method tokens to a canonical set.
        from types import SimpleNamespace
        parsed = ConfirmationEngine._allow_methods(
            SimpleNamespace(headers={"ALLOW": "get, Put"}))
        assert parsed == {"GET", "PUT"}

    def test_confirmed_severity_is_medium_never_critical(self):
        # A write-enabled PRECONDITION (not proven RCE) is medium, never critical;
        # an unconfirmed result is info. All five aliases map the same.
        from hydra.main import HydraEngine
        for vc in ("dangerous_http_methods", "dangerous_methods",
                   "http_methods", "tomcat_partial_put", "partial_put"):
            confirmed = ConfirmationResult(
                target=self.TARGET, param="", vuln_class=vc, confirmed=True,
                evidence_level=EvidenceLevel.OBSERVED)
            pending = ConfirmationResult(
                target=self.TARGET, param="", vuln_class=vc, confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED)
            assert HydraEngine._confirm_severity(vc, confirmed) == "medium"
            assert HydraEngine._confirm_severity(vc, pending) == "info"

    def test_poc_is_options_only_no_write_verb(self):
        # The PoC reproduces with a single bodyless OPTIONS; it never carries a
        # write verb or a request body / upload flag.
        engine, _ = _dangerous_methods_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        assert "-X OPTIONS" in res.poc
        assert "-X PUT" not in res.poc
        assert "-X DELETE" not in res.poc and "-X PATCH" not in res.poc
        assert "-d " not in res.poc and "--data" not in res.poc
        assert "-F " not in res.poc and "--form" not in res.poc
        assert "-T " not in res.poc and "--upload-file" not in res.poc
        # the note names the refused write chain in plain terms.
        assert "partial-PUT" in res.note
        assert "serialized-session gadget" in res.note

    def test_never_exploit_invariant(self):
        # No sent URL is ever an exploitation payload, every verb on the wire is
        # OPTIONS (never a write / GET), and the PoC sends no write verb or body.
        engine, fetch = _dangerous_methods_engine(self._responder())
        res = _run(engine.confirm(self.TARGET, "", "dangerous_http_methods",
                                  nonce=self.NONCE))
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url
        assert set(fetch.methods) == {"OPTIONS"}
        for bad in ("PUT", "DELETE", "PATCH", "GET", "POST"):
            assert bad not in fetch.methods, bad
        assert "curl -X POST" not in res.poc
        assert "-X PUT" not in res.poc
    def test_candidates_strip_query_and_dedupe(self):
        # The candidate list strips query/fragment, puts the operator-supplied
        # path first, always includes the origin root, and never duplicates.
        cands = ConfirmationEngine._dangerous_method_candidates(
            "https://tc.t.tld/manager/?x=1#frag")
        assert cands[0] == "https://tc.t.tld/manager/"
        for c in cands:
            assert "?" not in c and "#" not in c
        assert "https://tc.t.tld/" in cands
        assert len(cands) == len(set(cands))
        # A root-only target collapses to a single entry.
        root_only = ConfirmationEngine._dangerous_method_candidates(
            "https://tc.t.tld/")
        assert root_only == ["https://tc.t.tld/"]

    def test_constants_are_benign(self):
        assert _DANGEROUS_WRITE_METHODS == ("PUT", "DELETE", "PATCH")
        assert _PARTIAL_PUT_METHOD == "PUT"
        for banner in ("Apache-Coyote/1.1", "Apache Tomcat/9.0.80",
                       "Coyote"):
            assert _TOMCAT_SERVER_RE.search(banner)
        assert not _TOMCAT_SERVER_RE.search("nginx/1.25.3")
        assert not _TOMCAT_SERVER_RE.search("")








