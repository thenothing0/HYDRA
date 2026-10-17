"""Offline tests for the autonomous hunt path (Path B) — no real net/subprocess.

MCP calls and the HTTP fetch are injected, so this module never opens a socket.
Its core purpose is to lock in HYDRA's **never-exploit** invariant: the hunt
engine may only ever transmit curated *benign* detection probes, never the
exploitation payloads carried in ``strategies.py``.
"""

import asyncio

import pytest

from hydra.hunt import HuntEngine
from hydra.hunt.strategies import STRATEGY_REGISTRY, get_strategy
from hydra.hunt.safety import (
    EvidenceLevel, is_exploitation_payload, benign_probes_for, assess_probe,
    benign_probe_variants, encoded_variants, BENIGN_PROBES,
    is_safe_probe_header, sanitize_probe_headers,
    _fold_unicode, _normalize,
)
from hydra.hunt.prober import (
    SafeProber, build_probe_url, HandshakeResponse,
)


def _run(coro):
    return asyncio.run(coro)


# ── fakes ──────────────────────────────────────────
class FakeMCP:
    """Stands in for MCPClient — records calls, returns canned tool output."""

    def __init__(self, output="", success=True):
        self.output, self.success = output, success
        self.calls = []

    async def execute_tool(self, tool_name, params, timeout=None):
        self.calls.append((tool_name, dict(params)))
        return {"success": self.success, "output": self.output,
                "tool_used": tool_name, "return_code": 0}


class RecordingFetch:
    """Injectable async fetch(url) -> (status, headers, body); records every URL."""

    def __init__(self, responder=None):
        self.urls = []
        self._responder = responder or (lambda url: (200, {}, ""))

    async def __call__(self, url):
        self.urls.append(url)
        return self._responder(url)


class HeaderRecordingFetch:
    """Header-aware injectable fetch: ``async fetch(url, headers=None)``.

    Two positional args, so ``SafeProber._fetch_accepts_headers()`` returns True
    and a benign marker header (e.g. CVE-2025-29927's ``x-middleware-subrequest``)
    actually reaches the responder. Records every ``(url, headers)`` pair.
    """

    def __init__(self, responder=None):
        self.calls = []              # list of (url, headers_dict)
        self._responder = responder or (lambda url, headers: (200, {}, ""))

    async def __call__(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        return self._responder(url, dict(headers or {}))


class HandshakeRecordingFake:
    """Injectable handshake seam: ``async handshake_fetch(url, headers, method)``.

    Exactly three positional args and NO body slot — the primitive can never
    hand it a request body, which is the structural half of enabler #6's
    never-exploit contract (bodyless capture, no WS/h2 frame). Records every
    ``(url, headers, method)`` call and returns a canned status-line dict.
    """

    def __init__(self, result=None):
        self.calls = []                      # list of (url, headers, method)
        self._result = result if result is not None else {"codes": [200]}

    async def __call__(self, url, headers, method):
        self.calls.append((url, dict(headers or {}), method))
        return dict(self._result)


class _Scope:
    """Minimal scope-engine stand-in (loaded + allow/deny by substring)."""

    def __init__(self, loaded=True, allow_host=""):
        self.is_loaded = loaded
        self._allow_host = allow_host

    def validate_target(self, host):
        from types import SimpleNamespace
        ok = (not self._allow_host) or (self._allow_host in host)
        return SimpleNamespace(allowed=ok, reason="" if ok else "oos")


# ═══════════════════════════════════════════════════
#  safety.py — denylist, benign probes, evidence judge
# ═══════════════════════════════════════════════════
class TestSafety:
    @pytest.mark.parametrize("payload", [
        "{{7*7*7}}__globals__", "'; DROP TABLE users--", "1 UNION SELECT pw",
        "http://169.254.169.254/latest/meta-data", "../../../etc/passwd",
        "<script>alert(1)</script>", "javascript:alert(document.cookie)",
        "file:///etc/passwd", "' OR '1'='1", "1' waitfor delay '0:0:5'--",
    ])
    def test_exploitation_payloads_flagged(self, payload):
        assert is_exploitation_payload(payload) is True

    def test_empty_is_not_exploitation(self):
        assert is_exploitation_payload("") is False
        assert is_exploitation_payload(None) is False

    def test_every_curated_probe_is_benign(self):
        # The whole point: nothing the engine is allowed to send may be
        # exploitation-grade — payload AND control alike.
        for vc, probes in BENIGN_PROBES.items():
            for p in probes:
                assert not is_exploitation_payload(p.payload), (vc, p.payload)
                assert not is_exploitation_payload(p.control), (vc, p.control)

    @pytest.mark.parametrize("vc", ["ssrf", "lfi", "idor", "authz", "rce", "cors"])
    def test_no_benign_param_probe_for_dangerous_classes(self, vc):
        # These classes have no *benign* injected value — only nuclei/path checks.
        assert benign_probes_for(vc) == []

    @pytest.mark.parametrize("vc", ["sqli", "ssti", "xss", "open_redirect"])
    def test_benign_probes_present_for_probeable_classes(self, vc):
        assert benign_probes_for(vc), vc

    def test_assess_redirect(self):
        p = benign_probes_for("open_redirect")[0]
        assert assess_probe(p, location="https://example.com/hydra") is True
        assert assess_probe(p, location="https://target.tld/home") is False

    def test_assess_reflect_verbatim_only(self):
        p = benign_probes_for("xss")[0]
        assert assess_probe(p, body=f"hello {p.payload} world") is True
        # HTML-encoded echo is NOT a verbatim reflection → negative.
        assert assess_probe(p, body="hello &lt;&gt; world") is False

    def test_assess_evaluate_needs_render_not_literal(self):
        p = next(x for x in benign_probes_for("ssti") if x.payload == "{{7*7}}")
        # rendered (49 present, literal gone) with a clean control → positive
        assert assess_probe(p, body="result: 49", control_body="result: 42") is True
        # literal survived → not evaluated → negative
        assert assess_probe(p, body="result: {{7*7}} = 49") is False
        # 49 also in control → coincidental → negative
        assert assess_probe(p, body="49", control_body="49") is False

    def test_assess_error_based_sqli(self):
        p = benign_probes_for("sqli")[0]
        assert assess_probe(p, body="You have an error in your SQL syntax") is True
        assert assess_probe(p, body="everything is fine") is False
        # signature also present without the probe (in control) → coincidental
        assert assess_probe(p, body="SQL syntax", control_body="SQL syntax") is False


# ═══════════════════════════════════════════════════
#  Encoded WAF-bypass: denylist unmasks harmful, benign variants pass
# ═══════════════════════════════════════════════════
class TestEncodedProbesAndDenylist:
    @pytest.mark.parametrize("encoded", [
        "%27%20OR%201=1",                 # ' OR 1=1
        "union%2F%2A%2A%2Fselect",        # union/**/select  (comment-split)
        "..%252fetc%252fpasswd",          # double-encoded ../etc/passwd
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%73leep(5)",                     # sleep(5)  (blind SQLi)
        "http://169.254.169.254%2Flatest",
    ])
    def test_denylist_unmasks_encoded_exploits(self, encoded):
        # Hardening: an exploit hidden behind (possibly nested) URL-encoding or
        # inline SQL comments is decoded/de-obfuscated before the check → blocked.
        assert is_exploitation_payload(encoded) is True

    @pytest.mark.parametrize("vc", ["sqli", "ssti", "xss", "open_redirect"])
    def test_encoded_variants_stay_benign(self, vc):
        # The whole point: encoding a benign probe to defeat a WAF must never
        # turn it exploitation-grade — payload AND control decode back to benign.
        for p in benign_probe_variants(vc):
            assert not is_exploitation_payload(p.payload), (vc, p.payload)
            assert not is_exploitation_payload(p.control), (vc, p.control)

    def test_variants_extend_base_with_encodings(self):
        base = benign_probes_for("sqli")
        variants = benign_probe_variants("sqli")
        assert len(variants) > len(base)                 # base + encodings
        # the plain probe is always tried first, encodings follow
        assert variants[0].payload == base[0].payload
        assert any("%27" in v.payload for v in variants)  # url-encoded quote

    @pytest.mark.parametrize("vc", ["ssrf", "lfi", "idor", "authz", "rce", "cors"])
    def test_no_variants_for_dangerous_classes(self, vc):
        assert benign_probe_variants(vc) == []            # still nothing to send

    def test_encoded_variant_preserves_judging_fields(self):
        base = benign_probes_for("ssti")[0]
        v = encoded_variants(base)[0]
        assert v.payload != base.payload                  # actually encoded
        assert v.signatures == base.signatures            # look for same result
        assert v.kind == base.kind and v.evidence == base.evidence
        assert v.literal == base.payload                  # decoded literal kept

    def test_assess_encoded_ssti_uses_decoded_literal(self):
        # An encoded {{7*7}} that the engine rendered → 49 present, decoded
        # literal absent, control clean → positive, same as the plain probe.
        base = next(p for p in benign_probes_for("ssti") if p.payload == "{{7*7}}")
        v = next(x for x in encoded_variants(base))
        assert assess_probe(v, body="out: 49", control_body="out: 42") is True
        # server echoed the *decoded* literal unrendered → not evaluated → negative
        assert assess_probe(v, body="out: {{7*7}} 49") is False


# ═══════════════════════════════════════════════════
#  Enabler #7 — WorstFit / Best-Fit Unicode folding
#  (denylist hole: look-alike Unicode sailed past the ASCII markers)
# ═══════════════════════════════════════════════════
class TestWorstFitFolding:
    # ── fold-level unit checks ──────────────────
    @pytest.mark.parametrize("obf,ascii_form", [
        ("／", "/"),      # fullwidth solidus  ／ → /
        ("＼", "\\"),     # fullwidth reverse solidus ＼ → \
        ("＂", '"'),      # fullwidth quotation mark ＂ → "
        ("­", "-"),      # soft hyphen        → -
        ("¥", "\\"),     # yen sign  ¥        → \
        ("₩", "\\"),     # won sign  ₩        → \
        ("⁄", "/"),      # fraction slash     → /
        ("∕", "/"),      # division slash     → /
        ("∖", "\\"),     # set-minus operator → \
        ("‘", "'"),      # left single quote  → '
        ("”", '"'),      # right double quote → "
    ])
    def test_fold_maps_lookalike_to_ascii(self, obf, ascii_form):
        assert ascii_form in _fold_unicode(f"x{obf}y")

    @pytest.mark.parametrize("zw", [
        "​", "‌", "‍", "⁠", "﻿", "‎", "‏",
    ])
    def test_fold_strips_zero_width(self, zw):
        # a zero-width char splitting `..X/` must be removed so it collapses to ../
        assert _fold_unicode(f"..{zw}/x") == "../x"

    def test_normalize_folds_after_percent_decode(self):
        # percent-encoded fullwidth solidus (%EF%BC%8F → ／ → /) unmasks traversal
        assert "../" in _normalize("..%EF%BC%8Fetc%EF%BC%8Fpasswd")

    # ── obfuscated exploits are now BLOCKED ─────
    @pytest.mark.parametrize("payload", [
        "..／etc／passwd",              # fullwidth-slash traversal
        "..%EF%BC%8Fetc%EF%BC%8Fpasswd",        # percent-encoded fullwidth "
        "1＂ OR ＂1＂=＂1",     # fullwidth-quote SQLi
        "..​/​../etc/passwd",         # zero-width-split traversal
        "T(java.lang.Runtime)",                 # SpEL qualified type ref
        "T( java.lang.Runtime )",               # spaced SpEL type ref
        "new java.lang.ProcessBuilder()",       # Java qualified constructor
        "${{new javax.script.ScriptEngineManager()}}",
        "config[__class]=1",                    # Yii nested-object gadget key
        "Class.forName('java.lang.Runtime')",   # reflective loader
        "obj.getClass().getName()",             # runtime class walk
        "new ProcessBuilder(cmd)",              # bare processbuilder marker
    ])
    def test_obfuscated_exploits_blocked(self, payload):
        assert is_exploitation_payload(payload) is True

    # ── benign probes + prose still PASS ────────
    @pytest.mark.parametrize("vc", list(BENIGN_PROBES.keys()))
    def test_all_benign_variants_still_pass(self, vc):
        for p in benign_probe_variants(vc):
            assert not is_exploitation_payload(p.payload), (vc, p.payload)
            assert not is_exploitation_payload(p.control), (vc, p.control)

    @pytest.mark.parametrize("prose", [
        "new items", "renew subscription", "the new user guide",
        "a new-account form", "newton's method", "renewal date",
        "brand new feature", "T(otal) results", "class of 2026",
    ])
    def test_prose_not_flagged(self, prose):
        # the qualified-type regexes must fire on code, never ordinary words
        assert is_exploitation_payload(prose) is False

    def test_fold_never_makes_benign_harmful(self):
        # folding is defense-in-depth only: a benign value stays benign
        for vc in BENIGN_PROBES:
            for p in benign_probes_for(vc):
                assert not is_exploitation_payload(_fold_unicode(p.payload))


# ═══════════════════════════════════════════════════
#  prober.py — the single guarded send point
# ═══════════════════════════════════════════════════
class TestProber:
    def test_build_probe_url_replaces_param(self):
        u = build_probe_url("https://t.tld/p?id=1&x=2", "id", "PROBE")
        # existing `id` is dropped and re-added with the probe value; `x` kept
        assert "id=PROBE" in u and "x=2" in u
        assert u.count("id=") == 1

    def test_build_probe_url_adds_missing_param(self):
        u = build_probe_url("https://t.tld/p", "q", "PROBE")
        assert "q=PROBE" in u

    def test_prober_refuses_exploitation_url(self):
        fetch = RecordingFetch()
        prober = SafeProber(fetch=fetch)
        resp = _run(prober.get("https://t.tld/?x=../../etc/passwd"))
        assert not resp.ok and "exploitation" in resp.error
        assert fetch.urls == []          # never transmitted
        assert prober.sent == 0

    def test_prober_scope_gate_refuses_out_of_scope(self):
        fetch = RecordingFetch()
        prober = SafeProber(scope_engine=_Scope(allow_host="in.tld"), fetch=fetch)
        resp = _run(prober.get("https://out.tld/x"))
        assert not resp.ok and "out of scope" in resp.error
        assert fetch.urls == []

    def test_prober_allows_in_scope_benign(self):
        fetch = RecordingFetch(lambda u: (200, {"X": "y"}, "hello"))
        prober = SafeProber(scope_engine=_Scope(allow_host="in.tld"), fetch=fetch)
        resp = _run(prober.get("https://in.tld/x"))
        assert resp.ok and resp.status == 200 and resp.body == "hello"
        assert fetch.urls == ["https://in.tld/x"]

    def test_prober_request_cap(self):
        fetch = RecordingFetch()
        prober = SafeProber(fetch=fetch, max_requests=2)
        for _ in range(4):
            _run(prober.get("https://t.tld/x"))
        assert prober.sent == 2          # hard ceiling honoured
        assert len(fetch.urls) == 2

    def test_prober_location_and_body_cap(self):
        fetch = RecordingFetch(lambda u: (301, {"Location": "https://z/"}, "x" * 100))
        prober = SafeProber(fetch=fetch, max_body=10)
        resp = _run(prober.get("https://t.tld/x"))
        assert resp.location == "https://z/"
        assert len(resp.body) == 10      # body read is bounded

    def test_prober_fetch_exception_becomes_error_resp(self):
        async def boom(url):
            raise RuntimeError("kaboom")
        prober = SafeProber(fetch=boom)
        resp = _run(prober.get("https://t.tld/x"))
        assert not resp.ok and "kaboom" in resp.error   # never raises


# ═══════════════════════════════════════════════════
#  Header safety — RFC-token names, no CR/LF/NUL, never exploitation-grade
# ═══════════════════════════════════════════════════
class TestHeaderSafety:
    def test_benign_marker_header_is_safe(self):
        assert is_safe_probe_header("x-middleware-subrequest", "middleware") is True
        assert is_safe_probe_header("X-Forwarded-For", "203.0.113.7") is True
        assert is_safe_probe_header("X-Empty", None) is True   # empty value ok

    @pytest.mark.parametrize("name", [
        "", "bad header", "X-Foo:bar", "X-Foo\tbar", "X-Foo\n", "hea/der",
    ])
    def test_non_token_names_refused(self, name):
        assert is_safe_probe_header(name, "v") is False

    @pytest.mark.parametrize("value", [
        "a\r\nb", "a\nb", "a\rb", "a\x00b",
        "v%0d%0aInjected: 1",             # url-encoded CRLF → request splitting
        "v%250d%250aInjected: 1",         # double-encoded CRLF
    ])
    def test_crlf_nul_values_refused(self, value):
        # No line break — raw or (nested) percent-encoded — may reach the wire.
        assert is_safe_probe_header("X-Foo", value) is False

    @pytest.mark.parametrize("value", [
        "http://169.254.169.254/latest/meta-data",
        "../../../etc/passwd", "'; DROP TABLE users--",
        "<script>alert(1)</script>", "file:///etc/passwd",
    ])
    def test_exploitation_grade_values_refused(self, value):
        # A header may carry a benign differential marker, never an exploit.
        assert is_safe_probe_header("X-Probe", value) is False

    def test_sanitize_splits_safe_from_rejected_order_preserving(self):
        safe, rejected = sanitize_probe_headers({
            "X-Ok": "1", "Bad Name": "2", "X-Inj": "a\r\nb",
            "X-Meta": "http://169.254.169.254/", "X-Fine": "yes",
        })
        assert safe == {"X-Ok": "1", "X-Fine": "yes"}
        assert rejected == ["Bad Name", "X-Inj", "X-Meta"]   # order preserved

    def test_sanitize_none_is_empty(self):
        assert sanitize_probe_headers(None) == ({}, [])
        assert sanitize_probe_headers({}) == ({}, [])

    def test_sanitize_coerces_value_to_str(self):
        safe, rejected = sanitize_probe_headers({"X-Num": 5})
        assert safe == {"X-Num": "5"} and rejected == []


# ═══════════════════════════════════════════════════
#  Prober header path — benign header transmitted, unsafe refuses WHOLE probe
# ═══════════════════════════════════════════════════
class TestProberHeaders:
    def test_benign_header_is_transmitted(self):
        fetch = HeaderRecordingFetch(lambda u, h: (200, {}, "ok"))
        prober = SafeProber(fetch=fetch)
        resp = _run(prober.get("https://t.tld/x",
                               headers={"x-middleware-subrequest": "middleware"}))
        assert resp.ok and resp.status == 200
        # header-aware fetch called as fetch(url, headers) — marker delivered
        assert fetch.calls == [
            ("https://t.tld/x", {"x-middleware-subrequest": "middleware"})]

    def test_unsafe_header_refuses_whole_probe_failclosed(self):
        # One bad header taints the set: NOTHING is sent, not even the safe one.
        fetch = HeaderRecordingFetch(lambda u, h: (200, {}, "ok"))
        prober = SafeProber(fetch=fetch)
        resp = _run(prober.get("https://t.tld/x",
                               headers={"X-Ok": "1", "X-Inj": "a\r\nb"}))
        assert not resp.ok and "unsafe header" in resp.error
        assert "X-Inj" in resp.error
        assert fetch.calls == []            # fail-closed — whole probe refused
        assert prober.sent == 0

    @pytest.mark.parametrize("headers", [
        {"X-Url": "http://169.254.169.254/latest/meta-data"},   # SSRF metadata
        {"X-Path": "../../../etc/passwd"},                       # traversal
        {"X-Foo": "v%0d%0aInjected: 1"},                         # encoded CRLF
        {"bad header": "x"},                                     # non-token name
    ])
    def test_exploitation_and_injection_headers_refused(self, headers):
        fetch = HeaderRecordingFetch(lambda u, h: (200, {}, "ok"))
        prober = SafeProber(fetch=fetch)
        resp = _run(prober.get("https://t.tld/x", headers=headers))
        assert not resp.ok and "unsafe header" in resp.error
        assert fetch.calls == []            # never transmitted

    def test_legacy_one_arg_fetch_backward_compatible(self):
        # A pre-existing fetch(url) fake is STILL called as fetch(url): a safe
        # header is silently dropped (not double-sent), nothing raises.
        fetch = RecordingFetch(lambda u: (200, {}, "ok"))
        prober = SafeProber(fetch=fetch)
        resp = _run(prober.get("https://t.tld/x",
                               headers={"x-middleware-subrequest": "middleware"}))
        assert resp.ok
        assert fetch.urls == ["https://t.tld/x"]   # one call, no header arg


# ═══════════════════════════════════════════════════
#  Handshake / interim-status capture (enabler #6) — bodyless, no frames
# ═══════════════════════════════════════════════════
class TestProberHandshake:
    # ── status-line interpretation ─────────────────
    def test_switching_protocols_101_is_switched(self):
        fake = HandshakeRecordingFake({"codes": [101], "reason": "Switching Protocols",
                                       "status_line": "HTTP/1.1 101 Switching Protocols",
                                       "headers": {"Upgrade": "websocket"}})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/ws"))
        assert isinstance(resp, HandshakeResponse)
        assert resp.ok and resp.status == 101
        assert resp.switched is True
        assert resp.saw_continue is False and resp.expectation_failed is False
        assert resp.codes == [101]
        assert resp.headers == {"Upgrade": "websocket"}
        assert resp.status_line == "HTTP/1.1 101 Switching Protocols"

    def test_interim_100_then_final_200_both_captured(self):
        # Expect: 100-continue honoured: an interim 100 precedes the final 200.
        fake = HandshakeRecordingFake({"codes": [100, 200], "reason": "OK"})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x",
                                     headers={"Expect": "100-continue"}))
        assert resp.saw_continue is True
        assert resp.status == 200          # last code is the final/terminal one
        assert resp.codes == [100, 200]
        assert resp.switched is False and resp.expectation_failed is False

    def test_expectation_failed_417(self):
        fake = HandshakeRecordingFake({"codes": [417], "reason": "Expectation Failed"})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x",
                                     headers={"Expect": "100-continue"}))
        assert resp.expectation_failed is True
        assert resp.status == 417 and resp.saw_continue is False

    def test_timeout_marks_timed_out_not_error(self):
        # No status line read (waiting for a body we never send) → timed_out.
        fake = HandshakeRecordingFake({"timed_out": True})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x"))
        assert resp.timed_out is True
        assert resp.status == 0 and not resp.ok and resp.error == ""

    def test_transport_error_surfaced(self):
        fake = HandshakeRecordingFake({"error": "connect failed: refused"})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x"))
        assert not resp.ok and "connect failed" in resp.error

    def test_default_method_is_get(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        _run(prober.handshake("https://t.tld/ws"))
        assert fake.calls[0][2] == "GET"

    # ── never-exploit: only safe bodyless verbs reach the wire ─────
    @pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "POST", "put"])
    def test_write_verb_refused_before_any_send(self, method):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x", method=method))
        assert not resp.ok
        assert resp.error == f"refused: unsafe handshake method {method}"
        assert fake.calls == []            # nothing transmitted
        assert prober.sent == 0            # and nothing counted

    @pytest.mark.parametrize("method", ["GET", "OPTIONS", "HEAD"])
    def test_safe_bodyless_methods_allowed(self, method):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/x", method=method))
        assert resp.switched is True
        assert fake.calls[0][2] == method

    def test_fake_only_ever_gets_three_args_no_body(self):
        # Structural half of the contract: the primitive hands the seam exactly
        # (url, headers, method) — there is no body slot to smuggle a frame into.
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        _run(prober.handshake("https://t.tld/ws"))
        assert len(fake.calls) == 1
        url, headers, method = fake.calls[0]   # unpacks iff arity is exactly 3
        assert url == "https://t.tld/ws" and method == "GET"

    def test_cswsh_handshake_headers_pass_the_gauntlet(self):
        # The CSWSH precondition headers (Upgrade/Connection/Sec-WebSocket-*/a
        # foreign Origin) are benign tokens — they must reach the seam intact.
        hs = {
            "Upgrade": "websocket", "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Origin": "https://foreign.example",
        }
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/ws", headers=dict(hs)))
        assert resp.switched is True
        assert fake.calls[0][1] == hs      # delivered verbatim, none rejected

    # ── the IDENTICAL fail-closed gauntlet as get()/options() ──────
    def test_exploitation_url_refused(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/?x=../../etc/passwd"))
        assert not resp.ok and "exploitation" in resp.error
        assert fake.calls == [] and prober.sent == 0

    def test_out_of_scope_refused(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(scope_engine=_Scope(allow_host="in.tld"),
                            handshake_fetch=fake)
        resp = _run(prober.handshake("https://out.tld/ws"))
        assert not resp.ok and "out of scope" in resp.error
        assert fake.calls == []

    def test_unsafe_header_refuses_whole_handshake(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake("https://t.tld/ws",
                                     headers={"Upgrade": "websocket",
                                              "X-Inj": "a\r\nb"}))
        assert not resp.ok and "unsafe header" in resp.error and "X-Inj" in resp.error
        assert fake.calls == [] and prober.sent == 0

    def test_unsafe_credential_header_refuses_whole_handshake(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        resp = _run(prober.handshake(
            "https://t.tld/ws",
            credential_headers={"Authorization": "Bearer a\r\nb"}))
        assert not resp.ok and "unsafe credential header" in resp.error
        assert fake.calls == []

    def test_credential_header_value_relaxed_and_delivered(self):
        # A real token value may carry ``--``/``==``; the relaxed credential
        # sanitizer forwards it verbatim (name still token-checked, CR/LF/NUL
        # still rejected). It must reach the operator's own endpoint.
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake)
        token = "Bearer ey--J0.ab/*c.d=="
        resp = _run(prober.handshake(
            "https://t.tld/ws", credential_headers={"Authorization": token}))
        assert resp.switched is True
        assert fake.calls[0][1] == {"Authorization": token}

    def test_request_cap_blocks_further_handshakes(self):
        fake = HandshakeRecordingFake({"codes": [101]})
        prober = SafeProber(handshake_fetch=fake, max_requests=1)
        first = _run(prober.handshake("https://t.tld/ws"))
        second = _run(prober.handshake("https://t.tld/ws"))
        assert first.ok and not second.ok
        assert second.error == "request cap reached"
        assert prober.sent == 1 and len(fake.calls) == 1

    def test_real_raw_handshake_used_when_no_fake(self):
        # With no injected seam, _do_handshake must route to the real raw-socket
        # capture; we don't open a socket here, only prove the dispatch choice.
        prober = SafeProber()
        assert prober._handshake_fetch is None

    # ── _parse_status_lines (pure, offline) ────────
    def test_parse_single_terminal_101(self):
        text = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        p = SafeProber._parse_status_lines(text)
        assert p["codes"] == [101]
        assert p["reason"] == "Switching Protocols"
        assert p["status_line"] == "HTTP/1.1 101 Switching Protocols"
        assert p["headers"] == {"Upgrade": "websocket", "Connection": "Upgrade"}

    def test_parse_interim_100_then_200(self):
        text = ("HTTP/1.1 100 Continue\r\n\r\n"
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        p = SafeProber._parse_status_lines(text)
        assert p["codes"] == [100, 200]
        assert p["reason"] == "OK"                       # LAST status line's reason
        assert p["status_line"] == "HTTP/1.1 100 Continue"   # FIRST line verbatim
        assert p["headers"] == {"Content-Type": "text/html"}  # LAST block's fields

    def test_parse_417(self):
        p = SafeProber._parse_status_lines("HTTP/1.1 417 Expectation Failed\r\n\r\n")
        assert p["codes"] == [417] and p["reason"] == "Expectation Failed"

    def test_parse_tolerates_bare_lf_separators(self):
        p = SafeProber._parse_status_lines("HTTP/1.1 101 Switching Protocols\n\n")
        assert p["codes"] == [101]

    def test_parse_empty_and_garbage(self):
        assert SafeProber._parse_status_lines("")["codes"] == []
        assert SafeProber._parse_status_lines(None)["codes"] == []
        assert SafeProber._parse_status_lines("not http at all\r\n\r\n")["codes"] == []

    def test_parse_http2_version_token(self):
        p = SafeProber._parse_status_lines("HTTP/2 200\r\n\r\n")
        assert p["codes"] == [200] and p["reason"] == ""


# ═══════════════════════════════════════════════════
#  THE never-exploit invariant — nothing exploitation-grade hits the wire
# ═══════════════════════════════════════════════════
class TestNeverExploitInvariant:
    def _engine_with(self, fetch, nuclei_out=""):
        prober = SafeProber(fetch=fetch)          # no scope loaded → engine gate decides
        return HuntEngine(mcp_client=FakeMCP(output=nuclei_out),
                          active_probing=True, prober=prober)

    def test_no_exploitation_url_for_any_class(self):
        # Drive every strategy in the registry with active probing ON and record
        # every URL that reaches the wire. Not one may be exploitation-grade.
        fetch = RecordingFetch()
        engine = self._engine_with(fetch)
        for vc, strategy in STRATEGY_REGISTRY.items():
            _run(engine._execute_hunt_cycle("target.tld", vc, strategy, "normal"))
        assert fetch.urls, "expected at least one benign probe to be sent"
        for url in fetch.urls:
            assert is_exploitation_payload(url) is False, url

    def test_strategy_exploit_payloads_never_sent(self):
        # Belt-and-braces: no raw exploitation payload from any strategy's
        # ``.payloads`` list ever appears in a transmitted URL.
        fetch = RecordingFetch()
        engine = self._engine_with(fetch)
        for vc, strategy in STRATEGY_REGISTRY.items():
            _run(engine._execute_hunt_cycle("target.tld", vc, strategy, "normal"))
        sent = "\n".join(fetch.urls)
        for strategy in STRATEGY_REGISTRY.values():
            for payload in getattr(strategy, "payloads", []) or []:
                if is_exploitation_payload(payload):
                    assert payload not in sent, (strategy.vuln_class, payload)

    def test_probe_params_skips_exploitation_control(self, monkeypatch):
        # Even if a benign probe were mis-curated with an exploit control, the
        # prober's is_exploitation_payload gate drops it before the wire.
        fetch = RecordingFetch()
        prober = SafeProber(fetch=fetch)
        _run(prober.probe_param("https://t.tld/", "id", "../../etc/passwd"))
        assert fetch.urls == []           # refused, not sent


# ═══════════════════════════════════════════════════
#  HuntEngine cycle — nuclei-only (inactive) vs benign probing (active)
# ═══════════════════════════════════════════════════
_NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-1234","info":{"name":"Example Finding",'
    '"severity":"high"},"type":"http","host":"https://target.tld",'
    '"matched-at":"https://target.tld/x"}'
)


class TestHuntEngineCycle:
    def test_nuclei_only_when_inactive(self):
        # active_probing OFF → only Phase 1 nuclei runs, the prober is untouched.
        fetch = RecordingFetch()
        engine = HuntEngine(mcp_client=FakeMCP(output=_NUCLEI_JSONL),
                            active_probing=False,
                            prober=SafeProber(fetch=fetch))
        strat = get_strategy("sqli")
        findings = _run(engine._execute_hunt_cycle("target.tld", "sqli", strat, "normal"))
        assert fetch.urls == []                       # nothing probed live
        assert findings and findings[0]["hunt_source"] == "nuclei"
        assert findings[0]["hunt_class"] == "sqli"
        assert findings[0]["evidence_level"] == EvidenceLevel.OBSERVED
        assert findings[0]["template_id"] == "CVE-2021-1234"

    def test_no_mcp_client_skips_cycle(self):
        engine = HuntEngine(mcp_client=None)
        strat = get_strategy("sqli")
        assert _run(engine._execute_hunt_cycle("t.tld", "sqli", strat, "normal")) == []

    def test_active_error_based_sqli_detected(self):
        # Body carries a DB error only for the probe value; control is clean →
        # error-based positive, class-appropriate severity, INFERRED evidence.
        def responder(url):
            if "%27" in url or "%22" in url:          # url-encoded ' or "
                return (200, {}, "You have an error in your SQL syntax near '")
            return (200, {}, "everything ok")
        engine = HuntEngine(mcp_client=FakeMCP(output=""), active_probing=True,
                            prober=SafeProber(fetch=RecordingFetch(responder)))
        strat = get_strategy("sqli")
        findings = _run(engine._execute_hunt_cycle("target.tld", "sqli", strat, "normal"))
        sqli = [f for f in findings if f["hunt_source"] == "prober"]
        assert sqli, "expected a benign-probe SQLi lead"
        assert sqli[0]["severity"] == "high"
        assert sqli[0]["evidence_level"] == EvidenceLevel.INFERRED
        assert "benign probe" in sqli[0]["evidence"]

    def test_active_open_redirect_detected(self):
        # Location echoes the benign example.com canary → OBSERVED redirect lead.
        def responder(url):
            return (301, {"Location": "https://example.com/hydra"}, "")
        engine = HuntEngine(mcp_client=FakeMCP(output=""), active_probing=True,
                            prober=SafeProber(fetch=RecordingFetch(responder)))
        strat = get_strategy("open_redirect")
        findings = _run(engine._execute_hunt_cycle(
            "target.tld", "open_redirect", strat, "normal"))
        rd = [f for f in findings if f["hunt_source"] == "prober"]
        assert rd and rd[0]["severity"] == "medium"
        assert rd[0]["evidence_level"] == EvidenceLevel.OBSERVED

    def test_full_hunt_session_single_class(self):
        engine = HuntEngine(mcp_client=FakeMCP(output=_NUCLEI_JSONL))
        session = _run(engine.hunt("target.tld", vuln_class="sqli", mode="normal"))
        assert session.status.value == "completed"
        assert session.total_findings >= 1
        assert session.vuln_classes_tested == ["sqli"]


# ═══════════════════════════════════════════════════
#  _wf_hunt — CLI-level integration (offline, nuclei only)
# ═══════════════════════════════════════════════════
class TestWfHunt:
    def test_wf_hunt_nuclei_only(self, tmp_path):
        from hydra.main import HydraEngine
        eng = HydraEngine(target="target.tld", workflow="hunt",
                          output_dir=str(tmp_path), hunt_class="sqli",
                          hunt_mode="normal", hunt_active=False)
        eng.mcp = FakeMCP(output=_NUCLEI_JSONL)
        eng._scope = None                     # no scope loaded in this unit test
        _run(eng._wf_hunt())
        assert eng.findings and eng.findings[0]["hunt_source"] == "nuclei"
        # the nuclei tool was actually invoked (not simulated)
        assert any(name == "nuclei_scan" for name, _ in eng.mcp.calls)
        saved = tmp_path / "target.tld" / "scans" / "hunt_findings.json"
        assert saved.exists()

    def test_wf_hunt_dedupes_nuclei_by_template_id(self, tmp_path):
        # Two cycles returning the same template id collapse to one finding.
        from hydra.main import HydraEngine
        eng = HydraEngine(target="target.tld", workflow="hunt",
                          output_dir=str(tmp_path), hunt_class="auto",
                          hunt_mode="normal", hunt_active=False)
        eng.mcp = FakeMCP(output=_NUCLEI_JSONL)  # same tid every cycle
        eng._scope = None
        _run(eng._wf_hunt())
        tids = [f.get("template_id") for f in eng.findings if f.get("template_id")]
        assert tids.count("CVE-2021-1234") == 1



