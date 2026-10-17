"""CacheChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from urllib.parse import urlparse, parse_qsl, quote
from hydra.hunt.safety import EvidenceLevel
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import (
    _CACHE_STATUS_HEADERS,
    _IMG_ACCEPT_A,
    _IMG_ACCEPT_B,
    _IMG_LOCAL_CANDIDATES,
    _IMG_VARY_HEADER,
    _NEXT_IMAGE_PATH,
)

logger = logging.getLogger("hydra.hunt.confirm")


class CacheChecks:
    async def _confirm_web_cache(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2025-57752 proof: an Image-Optimizer cache-key confusion.

        The Next.js image optimizer negotiates the output format from the request
        ``Accept`` header but omits it from the cache key on vulnerable versions.
        HYDRA proves ONLY that mis-keying PRESENCE, and never poisons a real user:
        every request carries a UNIQUE nonce inside the inner ``url`` value (which
        the optimizer keys on), so each cache entry is isolated to the operator.
        Per fresh-nonce round: request A (Accept #1) populates the entry, then
        request B (Accept #2 — a DIFFERENT negotiated format) hits the SAME key on
        B's first-ever send. If B is served a cache HIT of A (proven from the
        target's OWN cache-status headers / Age), the Accept header is confused
        out of the key. GET-only, a benign image is read, ZERO other-user content
        is touched. This is a PRECONDITION (mis-keying) — cross-user poisoning
        IMPACT is deliberately NOT demonstrated, so it caps at OBSERVED.
        """
        nonce = nonce or uuid.uuid4().hex[:12]
        origin = self._origin(target_url)
        tech = "CVE-2025-57752 Next.js Image Optimization cache-key confusion"
        exchanges: List[ProbeExchange] = []

        # Reuse a known-good /_next/image request if the operator handed us one;
        # else probe benign local raster images against {origin}/_next/image.
        known = self._image_query(target_url)
        candidates = (
            [known] if known else [(c, "640", "75") for c in _IMG_LOCAL_CANDIDATES]
        )

        picked = None  # (inner, w, q) once a 200 is found
        confirming = miss_rounds = unknown_rounds = tested = 0
        proof = None  # first confirming round's details
        inconclusive = ""
        for i in range(self.repeats + 1):
            rnonce = f"{nonce}{i:02d}"
            # (A) Populate with Accept #1. On the first round, also DISCOVER which
            # candidate image yields a cacheable optimized 200.
            if picked is None:
                a = None
                for cand in candidates:
                    a_url = self._image_url(origin, cand, rnonce)
                    a = await prober.get(
                        a_url, headers={_IMG_VARY_HEADER: _IMG_ACCEPT_A}
                    )
                    exchanges.append(
                        ProbeExchange(
                            "control",
                            a.url,
                            a.status,
                            f"Accept #1 populate (nonce={rnonce})",
                        )
                    )
                    if a.ok and 200 <= a.status < 300:
                        picked = cand
                        break
                if picked is None:
                    return ConfirmationResult(
                        target=origin,
                        param="",
                        vuln_class="web_cache",
                        confirmed=False,
                        evidence_level=EvidenceLevel.OBSERVED,
                        exchanges=exchanges,
                        technique=tech,
                        summary=(
                            "Could not obtain a cacheable optimized image "
                            "from /_next/image (no benign local raster image "
                            "returned HTTP 200) — cannot test the optimizer "
                            "cache key. Re-run pointing --confirm-target at a "
                            "known-good /_next/image?url=...&w=...&q=... URL."
                        ),
                    )
            else:
                a_url = self._image_url(origin, picked, rnonce)
                a = await prober.get(a_url, headers={_IMG_VARY_HEADER: _IMG_ACCEPT_A})
                exchanges.append(
                    ProbeExchange(
                        "control",
                        a.url,
                        a.status,
                        f"Accept #1 populate (nonce={rnonce})",
                    )
                )
                if not (a.ok and 200 <= a.status < 300):
                    continue

            # A must be OUR fresh entry. If A is itself already a cache HIT, a
            # coarse upstream cache shares this key with others — we could not
            # attribute B's HIT to the differing Accept, so skip this round.
            if self._cache_state(a) == "hit":
                exchanges.append(
                    ProbeExchange(
                        "note",
                        a.url,
                        a.status,
                        "populate already a cache HIT — cannot isolate this round",
                    )
                )
                inconclusive = (
                    "the populate request was already served from "
                    "cache (a coarse upstream cache shares this key), "
                    "so a HIT cannot be attributed to the Accept header"
                )
                continue

            # (B) SAME key, a DIFFERENT response-affecting Accept, first-ever send.
            b_url = self._image_url(origin, picked, rnonce)
            b = await prober.get(b_url, headers={_IMG_VARY_HEADER: _IMG_ACCEPT_B})
            exchanges.append(
                ProbeExchange(
                    "payload",
                    b.url,
                    b.status,
                    f"Accept #2 same key, first send (nonce={rnonce})",
                )
            )
            if not (b.ok and 200 <= b.status < 300):
                continue
            tested += 1
            state = self._cache_state(b)
            if state == "hit":
                confirming += 1
                if proof is None:
                    proof = (
                        picked,
                        rnonce,
                        a.status,
                        b.status,
                        self._same_identity(a, b),
                    )
            elif state == "miss":
                miss_rounds += 1
            else:
                unknown_rounds += 1

        if confirming >= 1:
            cand, rnonce0, a_st, b_st, identical = proof
            held = (
                f"; observed on {confirming} of {tested} isolated round(s)"
                if tested > 1
                else ""
            )
            return ConfirmationResult(
                target=f"{origin}{_NEXT_IMAGE_PATH}",
                param="",
                vuln_class="web_cache",
                confirmed=True,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                poc=self._web_cache_poc(origin, cand, rnonce0),
                summary=(
                    "Next.js Image Optimization cache-key confusion present "
                    "(CVE-2025-57752): the 'Accept' header changed the "
                    "negotiated format but was absent from the optimizer "
                    "cache key — a second request with a DIFFERENT Accept was "
                    f"served the first request's cached response (HTTP {b_st} "
                    "cache HIT on a fresh, operator-isolated key"
                    + (", byte-identical response" if identical else "")
                    + f"){held}. Only operator-owned nonce'd keys were used — "
                    "no real user's cache entry was touched."
                ),
                note=(
                    "PRECONDITION only: HYDRA proved the mis-keying (a header "
                    "that changes the response is not in the optimizer cache "
                    "key) using UNIQUE nonce'd keys isolated to the operator, so "
                    "nothing here poisons another user's response. Cross-user "
                    "cache-poisoning IMPACT was NOT demonstrated — confirm it "
                    "manually within your authorization. GET-only, benign image, "
                    "zero other-user content read."
                ),
            )

        if tested == 0:
            return ConfirmationResult(
                target=origin,
                param="",
                vuln_class="web_cache",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "Could not obtain a clean, operator-isolated A/B cache "
                    "pair"
                    + (f" — {inconclusive}" if inconclusive else "")
                    + ". No reliable cache-key differential."
                ),
            )
        if miss_rounds and not confirming:
            return ConfirmationResult(
                target=origin,
                param="",
                vuln_class="web_cache",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "The 'Accept' header participates in the optimizer cache "
                    f"key (a differing-Accept request missed the cache on "
                    f"{miss_rounds} isolated round(s)) — no cache-key "
                    "confusion observed (not vulnerable / patched)."
                ),
            )
        return ConfirmationResult(
            target=origin,
            param="",
            vuln_class="web_cache",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique=tech,
            summary=(
                "No cache-status signal was exposed (no Age / X-*-Cache / "
                "CF-Cache-Status header), so a HIT could not be distinguished "
                "from a MISS — cache-key confusion could not be determined."
            ),
        )

    @staticmethod
    def _image_query(url):
        """If ``url`` is already a ``/_next/image`` request, return its
        ``(inner_url, w, q)`` so HYDRA reuses the operator's known-good image;
        else ``None`` (fall back to probing local candidates)."""
        parts = urlparse(url or "")
        if _NEXT_IMAGE_PATH not in (parts.path or ""):
            return None
        qs = dict(parse_qsl(parts.query or "", keep_blank_values=True))
        inner = qs.get("url")
        if not inner:
            return None
        return (inner, qs.get("w", "640"), qs.get("q", "75"))

    @staticmethod
    def _image_url(origin, cand, nonce):
        """Build ``{origin}/_next/image?url=<inner+v=nonce>&w=&q=``.

        The nonce is injected INSIDE the inner ``url`` value (the optimizer keys
        on it), so the resulting cache entry is unique to the operator — no real
        user ever shares it. The inner value is url-encoded into the outer query."""
        inner, w, q = cand
        sep = "&" if "?" in inner else "?"
        inner_n = f"{inner}{sep}v={nonce}"
        enc = quote(inner_n, safe="")
        return f"{origin}{_NEXT_IMAGE_PATH}?url={enc}&w={w}&q={q}"

    @staticmethod
    def _cache_state(resp):
        """Classify a response as served-from-cache: ``hit`` | ``miss`` | ``unknown``.

        Reads ONLY cache-transparency headers the target itself exposes (Age and
        the CDN ``*-cache*`` status headers) — never response bodies. A HIT marker
        or ``Age>0`` ⇒ ``hit``; a present-but-not-HIT marker or ``Age==0`` ⇒
        ``miss``; nothing exposed ⇒ ``unknown`` (cannot tell)."""
        hdrs = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
        for h in _CACHE_STATUS_HEADERS:
            if h in hdrs and "HIT" in hdrs[h].upper():
                return "hit"
        age = hdrs.get("age")
        age_i = None
        if age is not None:
            try:
                age_i = int(age.strip())
            except (ValueError, AttributeError):
                age_i = None
        if age_i is not None and age_i > 0:
            return "hit"
        if any(h in hdrs for h in _CACHE_STATUS_HEADERS):
            return "miss"  # a cache-status header present, but not a HIT
        if age_i is not None:
            return "miss"  # Age present and 0 → freshly generated
        return "unknown"

    @staticmethod
    def _same_identity(a, b):
        """True if two responses share a non-empty strong identity (same cached
        object): equal ETag / Last-Modified / Content-Length / Content-Type."""

        def sig(r):
            h = {str(k).lower(): str(v) for k, v in (r.headers or {}).items()}
            return (
                h.get("etag", ""),
                h.get("last-modified", ""),
                h.get("content-length", ""),
                h.get("content-type", ""),
            )

        sa, sb = sig(a), sig(b)
        return sa == sb and any(sa)

    @staticmethod
    def _web_cache_poc(origin, cand, nonce):
        u = CacheChecks._image_url(origin, cand, nonce)
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-57752 Next.js Image Optimization cache-key confusion",
                "# (benign: a two-GET cache-STATE differential on a UNIQUE operator-nonce'd key,",
                "#  differing ONLY in the Accept header; reads a benign image, poisons no real user)",
                "# (A) populate the isolated key with Accept #1 — expect HTTP 200, fresh (cache MISS):",
                f"curl -si -H 'Accept: {_IMG_ACCEPT_A}' '{u}'",
                "# (B) SAME key, a DIFFERENT Accept (#2), first-ever send — a cache HIT here proves",
                "#     the Accept header is NOT in the optimizer cache key (mis-keying present):",
                f"curl -si -H 'Accept: {_IMG_ACCEPT_B}' '{u}'",
                "# NOTE: the v=<nonce> inside the inner url isolates this cache entry to YOU — no",
                "#   real user shares it, so nothing is poisoned. This proves only the PRECONDITION;",
                "#   confirm cross-user poisoning impact manually within your authorization.",
            ]
        )
