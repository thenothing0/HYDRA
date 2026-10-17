"""SourceAnalysis: existing checks without policy or payload changes."""

import logging
import re
from urllib.parse import urljoin
from hydra.hunt.confirmation.models import ProbeExchange


from hydra.hunt.confirmation.signatures import _MAX_JS_BUNDLES, _SCRIPT_SRC_RE

logger = logging.getLogger("hydra.hunt.confirm")


class SourceAnalysis:
    async def _collect_sources(
        self, target_url, prober, exchanges, max_bundles=_MAX_JS_BUNDLES
    ):
        """GET the target's OWN HTML then its ``<script src>`` bundles (GET-only,
        scope-gated: a foreign/out-of-scope CDN is refused fail-closed and simply
        contributes no source). Returns ``(html, [(url, body), ...], note)`` where
        ``html`` is None when the page itself did not respond. Reads served text
        ONLY — never executes a script, never triggers a sink, never sends a
        payload."""
        html_resp = await prober.get(target_url)
        exchanges.append(
            ProbeExchange(
                "control",
                html_resp.url or self._origin(target_url),
                html_resp.status,
                "GET target HTML (read served markup only)",
            )
        )
        if not html_resp.ok:
            return (None, [], html_resp.error or "target did not respond")
        html = html_resp.body or ""
        srcs = self._script_srcs(html, target_url)
        truncated = len(srcs) > max_bundles
        bundles = []
        for src in srcs[:max_bundles]:
            r = await prober.get(src)
            exchanges.append(
                ProbeExchange(
                    "fingerprint",
                    r.url or src,
                    r.status,
                    "GET served <script src> bundle (read source only)",
                )
            )
            if r.ok and (r.body or ""):
                bundles.append((r.url or src, r.body or ""))
        note = ""
        if truncated:
            note = (
                f"scanned the first {max_bundles} of {len(srcs)} script "
                "bundles (request budget)"
            )
        return (html, bundles, note)

    @staticmethod
    def _script_srcs(html, base_url):
        """Absolute URLs of every ``<script src>`` in ``html`` (dedup, order kept).
        Resolves relative / root-relative / protocol-relative refs against the
        target URL; drops ``data:`` and non-HTTP(S) refs."""
        base = base_url if "//" in (base_url or "") else "https://" + (base_url or "")
        out, seen = [], set()
        for m in _SCRIPT_SRC_RE.finditer(html or ""):
            src = (m.group(1) or "").strip()
            if not src or src.lower().startswith("data:"):
                continue
            full = urljoin(base, src)
            if full.lower().startswith(("http://", "https://")) and full not in seen:
                seen.add(full)
                out.append(full)
        return out

    @staticmethod
    def _semver(s):
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", s or "")
        return tuple(int(x) for x in m.groups()) if m else None

    @staticmethod
    def _ver_in_range(version, lo_hi):
        """lo inclusive, hi exclusive, over (major, minor, patch) tuples."""
        t = SourceAnalysis._semver(version)
        lo, hi = lo_hi
        return bool(t and lo <= t < hi)
