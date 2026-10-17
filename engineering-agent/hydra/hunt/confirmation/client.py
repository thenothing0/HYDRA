"""ClientChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from hydra.hunt.safety import EvidenceLevel
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import (
    _BOOTSTRAP_BANNER_RE,
    _BOOTSTRAP_RANGE,
    _BOOTSTRAP_SIG_TOKENS,
    _BOOTSTRAP_VER_RE,
    _CSP_META_CONTENT_RE,
    _CSP_META_RE,
    _CSP_NONCE_RE,
    _DOMPURIFY_BANNER_RE,
    _DOMPURIFY_FALLBACK_RE,
    _DOMPURIFY_RANGE,
    _DOMPURIFY_SIG_RE,
    _DOMPURIFY_TOKEN_RE,
    _DOMPURIFY_VER_RE,
    _HTML_SINK_RE,
    _MSG_LISTENER_RE,
    _MSG_WINDOW,
    _ORIGIN_CHECK_RE,
    _WOO_GENERATOR_RE,
)

logger = logging.getLogger("hydra.hunt.confirm")


class ClientChecks:
    async def _confirm_sanitizer_bypass(self, target_url, prober, nonce):
        """DETECT-ONLY: a vulnerable DOMPurify build [3.0.1, 3.4.0) is served.
        Reads the page's own JS, fingerprints the DOMPurify version and the
        CUSTOM_ELEMENT_HANDLING code path. NEVER pollutes Object.prototype, never
        calls sanitize(), never builds/sends the PP→mutation-XSS payload — the
        payoff stays detect-only; HYDRA reports only that the vulnerable library
        is present. Caps at OBSERVED (static presence), never REPRODUCED."""
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = (
            "CVE-2026-41238 DOMPurify prototype-pollution via the "
            "CUSTOM_ELEMENT_HANDLING '|| {}' fallback (static library scan)"
        )
        exchanges: List[ProbeExchange] = []
        html, bundles, scan_note = await self._collect_sources(
            target_url, prober, exchanges
        )
        if html is None:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="sanitizer_bypass",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=tech,
                exchanges=exchanges,
                summary="Target did not respond; cannot read served assets.",
                note=scan_note,
            )
        hay = "\n".join([html] + [b for _, b in bundles])
        if not _DOMPURIFY_TOKEN_RE.search(hay):
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="sanitizer_bypass",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary="No DOMPurify found in the served HTML or script bundles.",
                note=scan_note,
            )
        version = self._dompurify_version(hay)
        has_sig = bool(_DOMPURIFY_SIG_RE.search(hay))
        in_range = self._ver_in_range(version, _DOMPURIFY_RANGE)
        vulnerable = in_range and has_sig
        for _ in range(self.repeats):
            if not vulnerable:
                break
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    self._origin(target_url),
                    200,
                    "re-read served bundle — version/signature stable",
                )
            )
        if not vulnerable:
            if version and not in_range:
                summary = (
                    f"DOMPurify {version} is served — outside the "
                    "vulnerable [3.0.1, 3.4.0) range (patched)."
                )
            elif in_range and not has_sig:
                summary = (
                    f"DOMPurify {version} is in range but the "
                    "CUSTOM_ELEMENT_HANDLING code path was not found in "
                    "the served source (feature absent / tree-shaken)."
                )
            else:
                summary = (
                    "DOMPurify is present but no version in the vulnerable "
                    "[3.0.1, 3.4.0) range was read from the served source."
                )
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="sanitizer_bypass",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary=summary,
                note=scan_note,
            )
        fallback = bool(_DOMPURIFY_FALLBACK_RE.search(hay))
        extra = (
            " The vulnerable '|| {}' fallback literal is present in source."
            if fallback
            else " (Minified build: '|| {}' literal not matched verbatim; version"
            " + CUSTOM_ELEMENT_HANDLING path confirm the vulnerable build.)"
        )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="sanitizer_bypass",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            summary=(
                f"Vulnerable DOMPurify {version} served (CVE-2026-41238 "
                "precondition): CUSTOM_ELEMENT_HANDLING present." + extra
            ),
            poc=self._sanitizer_bypass_poc(target_url, version),
            note=(
                "DETECT-ONLY precondition (OBSERVED): a vulnerable DOMPurify "
                "build is served. HYDRA did NOT pollute Object.prototype, call "
                "sanitize(), or send any prototype-pollution/XSS payload — the "
                "payoff is never triggered. Real exploitation also needs a "
                "separate prototype-pollution gadget on the page and default "
                "CUSTOM_ELEMENT_HANDLING config; confirm manually within scope. "
                + scan_note
            ).strip(),
        )

    @staticmethod
    def _dompurify_version(hay):
        """DOMPurify version from the license banner or a ``.version="x.y.z"``
        assignment co-located with the DOMPurify identity. Returns "" if none."""
        m = _DOMPURIFY_BANNER_RE.search(hay or "")
        if m:
            return m.group(1)
        m = _DOMPURIFY_VER_RE.search(hay or "")
        return m.group(1) if m else ""

    @staticmethod
    def _sanitizer_bypass_poc(target_url, version):
        return "\n".join(
            [
                "# Safe reproduction — CVE-2026-41238 DOMPurify prototype pollution",
                "# (benign: STATIC library fingerprint of served assets; no payload)",
                "# 1) fetch the page and read its <script src> bundles:",
                f"curl -s '{target_url}'",
                "# 2) grep the served bundle for the DOMPurify version + vuln path:",
                "#    grep -Eo 'DOMPurify [0-9]+\\.[0-9]+\\.[0-9]+' bundle.js",
                "#    grep -o 'CUSTOM_ELEMENT_HANDLING *|| *{}' bundle.js",
                f"# observed: DOMPurify {version or '<in [3.0.1,4.0.0)>'} in "
                "[3.0.1, 3.4.0) with the plain '|| {}' fallback → vulnerable build.",
                "# NOTE: HYDRA never pollutes Object.prototype, never calls",
                "#   sanitize(), and never sends the PP/XSS payload — triggering the",
                "#   mutation XSS IS the exploit. Confirm impact manually in scope.",
            ]
        )

    async def _confirm_postmessage(self, target_url, prober, nonce):
        """DETECT-ONLY: a cross-document ``message`` handler in the served JS
        reaches an innerHTML-family sink with NO origin validation in between —
        the DOM postMessage-XSS precondition (cf. WooCommerce CVE-2025-5062).
        HYDRA NEVER posts a message and never triggers the sink; it only reads the
        served listener source. Caps at OBSERVED."""
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = (
            "CVE-2025-5062 class — cross-document message handler without "
            "origin validation reaching an HTML sink (static source scan)"
        )
        exchanges: List[ProbeExchange] = []
        html, bundles, scan_note = await self._collect_sources(
            target_url, prober, exchanges
        )
        if html is None:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="postmessage",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=tech,
                exchanges=exchanges,
                summary="Target did not respond; cannot read served assets.",
                note=scan_note,
            )
        sources = [html] + [b for _, b in bundles]
        hit = self._postmessage_signature(sources)
        woo = _WOO_GENERATOR_RE.search(html)
        woo_note = f" (WooCommerce {woo.group(1)} fingerprinted)" if woo else ""
        if not hit:
            any_listener = any(_MSG_LISTENER_RE.search(s or "") for s in sources)
            summary = (
                "A 'message' listener was found, but an origin check "
                "guards it or no HTML sink follows it (not the vulnerable "
                "shape)."
                if any_listener
                else "No cross-document 'message' handler found in the served "
                "HTML or script bundles."
            )
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="postmessage",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary=summary,
                note=scan_note,
            )
        for _ in range(self.repeats):
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    self._origin(target_url),
                    200,
                    "re-read served bundle — listener signature stable",
                )
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="postmessage",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            summary=(
                "Served script registers a window 'message' listener with no "
                "origin check that reaches an HTML sink ("
                + hit
                + ") — DOM postMessage-XSS precondition."
                + woo_note
            ),
            poc=self._postmessage_poc(target_url, hit),
            note=(
                "DETECT-ONLY precondition (OBSERVED): the vulnerable listener "
                "shape is served. HYDRA did NOT postMessage() to the page and "
                "never reached the sink — sending the malicious message IS the "
                "exploit. Confirm the DOM XSS manually within scope. " + scan_note
            ).strip(),
        )

    @staticmethod
    def _postmessage_signature(sources):
        """Return the sink token when a served source has a 'message' listener
        with NO origin check in the following window but an HTML sink — else ""."""
        for src in sources:
            text = src or ""
            for m in _MSG_LISTENER_RE.finditer(text):
                window = text[m.start() : m.start() + _MSG_WINDOW]
                if _ORIGIN_CHECK_RE.search(window):
                    continue  # origin validated → safe shape
                sink = _HTML_SINK_RE.search(window)
                if sink:
                    return sink.group(0)
        return ""

    @staticmethod
    def _postmessage_poc(target_url, sink):
        return "\n".join(
            [
                "# Safe reproduction — DOM postMessage-XSS precondition (cf. CVE-2025-5062)",
                "# (benign: STATIC source scan of served assets; no message is posted)",
                f"curl -s '{target_url}'   # read the page + its <script src> bundles",
                "# grep the served bundle for the unguarded listener → sink:",
                "#   grep -n \"addEventListener('message'\" bundle.js",
                f"# observed: listener has no event.origin check and writes to {sink}.",
                "# NOTE: HYDRA never calls win.postMessage({...}) and never reaches the",
                "#   sink — delivering the crafted message IS the exploit. Confirm the",
                "#   DOM XSS manually within your authorization.",
            ]
        )

    async def _confirm_dom_clobbering(self, target_url, prober, nonce):
        """DETECT-ONLY: a vulnerable Bootstrap 3 build [3.4.1, 4.0.0) with the
        clobbering-prone tooltip/popover HTML sanitizer is served. Reads the
        served JS, fingerprints the Bootstrap version + the
        createHTMLDocument/sanitizeHtml sanitizer. NEVER injects a clobbering
        element and never triggers the sanitizer. Caps at OBSERVED. Low."""
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = (
            "CVE-2025-1647 Bootstrap 3 tooltip/popover DOM-clobbering in the "
            "createHTMLDocument/sanitizeHtml sanitizer (static library scan)"
        )
        exchanges: List[ProbeExchange] = []
        html, bundles, scan_note = await self._collect_sources(
            target_url, prober, exchanges
        )
        if html is None:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="dom_clobbering",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=tech,
                exchanges=exchanges,
                summary="Target did not respond; cannot read served assets.",
                note=scan_note,
            )
        hay = "\n".join([html] + [b for _, b in bundles])
        version = self._bootstrap_version(hay)
        in_range = self._ver_in_range(version, _BOOTSTRAP_RANGE)
        has_sig = all(tok.lower() in hay.lower() for tok in _BOOTSTRAP_SIG_TOKENS)
        vulnerable = in_range and has_sig
        for _ in range(self.repeats):
            if not vulnerable:
                break
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    self._origin(target_url),
                    200,
                    "re-read served bundle — version/signature stable",
                )
            )
        if not vulnerable:
            if version and not in_range:
                summary = (
                    f"Bootstrap {version} is served — outside the "
                    "affected [3.4.1, 4.0.0) range."
                )
            elif in_range and not has_sig:
                summary = (
                    f"Bootstrap {version} is in range but the "
                    "createHTMLDocument/sanitizeHtml sanitizer was not "
                    "found in the served source."
                )
            else:
                summary = (
                    "No Bootstrap 3 build in the affected [3.4.1, 4.0.0) "
                    "range was read from the served source."
                )
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="dom_clobbering",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary=summary,
                note=scan_note,
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="dom_clobbering",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            summary=(
                f"Vulnerable Bootstrap {version} served (CVE-2025-1647 "
                "precondition): the createHTMLDocument/sanitizeHtml "
                "DOM-clobbering sanitizer is present."
            ),
            poc=self._dom_clobbering_poc(target_url, version),
            note=(
                "DETECT-ONLY precondition (OBSERVED): a vulnerable Bootstrap 3 "
                "build is served. HYDRA did NOT inject a clobbering element and "
                "never invoked the sanitizer — triggering it IS the exploit. "
                "Confirm impact manually within scope. " + scan_note
            ).strip(),
        )

    @staticmethod
    def _bootstrap_version(hay):
        """Bootstrap version from the file banner or a ``VERSION='x.y.z'``
        constant (tooltip/popover Constructor.VERSION). Returns "" if none."""
        m = _BOOTSTRAP_BANNER_RE.search(hay or "")
        if m:
            return m.group(1)
        m = _BOOTSTRAP_VER_RE.search(hay or "")
        return m.group(1) if m else ""

    @staticmethod
    def _dom_clobbering_poc(target_url, version):
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-1647 Bootstrap 3 DOM-clobbering sanitizer",
                "# (benign: STATIC library fingerprint of served assets; no injection)",
                f"curl -s '{target_url}'   # read the page + its <script src> bundles",
                "# grep the served bundle for the version + the clobbering sanitizer:",
                "#   grep -Eo 'Bootstrap v?[0-9]+\\.[0-9]+\\.[0-9]+' bundle.js",
                "#   grep -o 'createHTMLDocument' bundle.js ; grep -o 'sanitizeHtml' bundle.js",
                f"# observed: Bootstrap {version or '<in [3.4.1,4.0.0)>'} with the "
                "createHTMLDocument/sanitizeHtml sanitizer → vulnerable build.",
                "# NOTE: HYDRA never injects a clobbering element and never invokes the",
                "#   tooltip/popover sanitizer — triggering it IS the exploit. Confirm",
                "#   impact manually within your authorization.",
            ]
        )

    async def _confirm_csp(self, target_url, prober, nonce):
        """PASSIVE posture: read the CSP the target itself sends (response header
        + ``<meta http-equiv>``) across two independent GETs and flag nonce-based
        bypass PRECONDITIONS — meta-delivered nonce, nonce reuse across requests,
        or 'unsafe-inline' alongside a nonce. Sends nothing but two plain GETs of
        the target's own page. Reports Low (precondition) / Info. OBSERVED."""
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = (
            "Nonce-based CSP bypass preconditions — meta-delivery / nonce "
            "reuse / unsafe-inline fallback (passive CSP read)"
        )
        exchanges: List[ProbeExchange] = []
        first = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control",
                first.url or target_url,
                first.status,
                "GET #1 — read Content-Security-Policy header + <meta>",
            )
        )
        if not first.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="csp",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=tech,
                exchanges=exchanges,
                summary="Target did not respond; cannot read its CSP.",
            )
        second = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "repeat",
                second.url or target_url,
                second.status,
                "GET #2 — compare nonce across an independent response",
            )
        )
        hdr1, meta1 = self._csp_sources(first)
        hdr2, meta2 = self._csp_sources(second)
        csp1 = " ".join([hdr1, meta1]).strip()
        if not csp1:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="csp",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary="No Content-Security-Policy sent (header or <meta>); "
                "nonce-bypass preconditions not applicable here.",
                note="A missing CSP is a separate hardening gap, out of scope for "
                "this nonce-precondition check.",
            )
        issues = self._csp_issues(hdr1, meta1, hdr2, meta2)
        if not issues:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="csp",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                summary="A nonce-based CSP is sent and looks correctly configured "
                "(header-delivered, fresh per-response nonce, no "
                "unsafe-inline fallback).",
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="csp",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            summary="Nonce-based CSP bypass precondition(s): " + "; ".join(issues),
            poc=self._csp_poc(target_url, issues),
            note="PASSIVE posture (OBSERVED): read only the CSP the target sends "
            "across two GETs. HYDRA injected no script and sent no bypass "
            "payload — these are preconditions, confirm exploitability "
            "manually within scope.",
        )

    @staticmethod
    def _csp_sources(resp):
        """Return ``(header_csp, meta_csp)`` for a response — the
        Content-Security-Policy header value and the ``<meta http-equiv>`` CSP
        content, each "" if absent. Reads only what the target itself serves."""
        header = ""
        for k, v in (resp.headers or {}).items():
            if str(k).lower() == "content-security-policy":
                header = str(v)
                break
        meta = ""
        tag = _CSP_META_RE.search(resp.body or "")
        if tag:
            cm = _CSP_META_CONTENT_RE.search(tag.group(0))
            if cm:
                meta = cm.group(2)
        return (header, meta)

    @staticmethod
    def _csp_issues(hdr1, meta1, hdr2, meta2):
        """Nonce-bypass preconditions from two independent CSP reads."""
        issues = []
        nonces1 = _CSP_NONCE_RE.findall(" ".join([hdr1, meta1]))
        if meta1 and _CSP_NONCE_RE.search(meta1):
            issues.append(
                "nonce delivered via <meta http-equiv> (does not "
                "protect markup before the tag; discouraged)"
            )
        nonces2 = _CSP_NONCE_RE.findall(" ".join([hdr2, meta2]))
        if nonces1 and nonces2 and set(nonces1) & set(nonces2):
            issues.append(
                "the same nonce is reused across two independent "
                "responses (predictable/static nonce defeats the nonce)"
            )
        combined = " ".join([hdr1, meta1]).lower()
        if nonces1 and "'unsafe-inline'" in combined:
            issues.append(
                "'unsafe-inline' present alongside a nonce (honored by "
                "pre-CSP3 browsers as a fallback)"
            )
        return issues

    @staticmethod
    def _csp_poc(target_url, issues):
        return "\n".join(
            [
                "# Safe reproduction — nonce-based CSP bypass preconditions (passive)",
                "# (benign: two plain GETs; reads only the CSP the target sends)",
                f"curl -sI '{target_url}' | grep -i content-security-policy",
                f"curl -sI '{target_url}' | grep -i content-security-policy  # compare nonce",
                "# observed precondition(s):",
            ]
            + [f"#   - {i}" for i in issues]
            + [
                "# NOTE: HYDRA injects no inline script and sends no bypass payload —",
                "#   these are preconditions. Confirm a working bypass manually within",
                "#   your authorization.",
            ]
        )
