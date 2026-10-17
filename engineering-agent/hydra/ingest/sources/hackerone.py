"""HackerOne source adapter — public disclosed reports (Hacktivity).

Pulls PUBLICLY DISCLOSED reports from HackerOne's Hacktivity feed via the same
GraphQL endpoint the public hacktivity page uses (https://hackerone.com/graphql).
Only disclosed, public reports are returned — nothing behind authentication.

Supports from/size pagination over the search index so large pulls
(e.g. 1000 reports) work by walking pages of 100 until the requested
limit (or the total_count) is reached.

Notes / honesty:
  • This reads a public, published feed and rate-limits itself. Heavy pulls
    should be run responsibly; HackerOne may throttle (handled via backoff).
  • The GraphQL schema is maintained by HackerOne and can change. Parsing is
    intentionally defensive: every field is optional and missing data is
    skipped rather than raising.
"""

import logging
from typing import Any, Dict, List

from hydra.ingest.base import (
    SourceAdapter, Writeup, register, classify_category, classify_severity,
)

logger = logging.getLogger("hydra.ingest.hackerone")

# GraphQL query for disclosed hacktivity reports.
# HackerOne serves the public Hacktivity feed via the `search` field over the
# CompleteHacktivityReportIndex, paginated with from/size and sorted by the
# latest disclosable activity. (Verified against the live schema.)
_HACKTIVITY_QUERY = """
query HydraHacktivity($queryString: String!, $from: Int, $size: Int) {
  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: {field: "latest_disclosable_activity_at", direction: DESC}
  ) {
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        id
        latest_disclosable_activity_at
        severity_rating
        reporter { username }
        team { handle name }
        report {
          title
          url
          substate
          weakness { name }
        }
      }
    }
  }
}
"""


@register
class HackerOneAdapter(SourceAdapter):
    name = "hackerone"
    min_interval = 1.5          # polite pacing between GraphQL pages
    GRAPHQL = "https://hackerone.com/graphql"
    PAGE_SIZE = 100             # search index page size (from/size pagination)

    async def fetch(self, query: str = "", limit: int = 20) -> List[Writeup]:
        """Fetch up to `limit` disclosed reports, paginating as needed.

        `query` maps to HackerOne's hacktivity query_string (e.g. a keyword,
        or 'disclosed:true'). Empty query defaults to disclosed reports.
        """
        query_string = query or "disclosed:true"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        collected: List[Writeup] = []
        offset = 0
        pages = 0
        max_pages = (limit // self.PAGE_SIZE) + 2

        while len(collected) < limit and pages < max_pages:
            pages += 1
            page_size = min(self.PAGE_SIZE, limit - len(collected))
            variables = {"queryString": query_string, "from": offset, "size": page_size}
            data = await self._post_json(
                self.GRAPHQL,
                {"query": _HACKTIVITY_QUERY, "variables": variables},
                headers=headers,
            )
            items = self._extract_items(data)
            if items is None:
                logger.warning(f"[hackerone] page {pages}: no data (schema/rate/network)")
                break
            if not items:
                break     # exhausted

            for node in items:
                w = self._node_to_writeup(node)
                if w:
                    collected.append(w)

            offset += page_size
            if offset >= self._total_count(data):
                break

        logger.info(f"[hackerone] fetched {len(collected)} disclosed reports "
                    f"across {pages} page(s)")
        return collected[:limit]

    # ── Parsing helpers (defensive) ────────────
    @staticmethod
    def _extract_items(data: Any) -> Any:
        if not isinstance(data, dict):
            return None
        try:
            return list(data["data"]["search"]["nodes"])
        except (KeyError, TypeError):
            return None

    @staticmethod
    def _total_count(data: Any) -> int:
        try:
            return int(data["data"]["search"]["total_count"])
        except (KeyError, TypeError, ValueError):
            return 0

    def _node_to_writeup(self, node: Dict[str, Any]) -> Any:
        if not isinstance(node, dict):
            return None
        report = node.get("report") or {}
        title = report.get("title", "")
        url = report.get("url", "")
        if not title or not url:
            # Undisclosed / bounty-only items have no public report — skip.
            return None

        substate = report.get("substate", "") or ""
        weakness = (report.get("weakness") or {}).get("name", "") or ""
        text = f"{title}\n{weakness}\n{substate}"

        sev = (node.get("severity_rating") or "").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = classify_severity(text)

        # Categorise from the title + HackerOne's own weakness (CWE) label.
        category = classify_category(f"{title} {weakness}")
        if category == "misc" and weakness:
            category = self._weakness_to_category(weakness)
        team = node.get("team") or {}
        reporter = node.get("reporter") or {}

        return Writeup(
            source=self.name,
            title=title,
            url=url,
            content=self._strip_html(text)[:8000],
            category=category,
            severity=sev,
            author=reporter.get("username", ""),
            published=node.get("latest_disclosable_activity_at", ""),
            tags=[t for t in (weakness, team.get("handle", ""), substate) if t],
        )

    @staticmethod
    def _weakness_to_category(weakness: str) -> str:
        """Map HackerOne CWE weakness names to our category slugs."""
        w = weakness.lower()
        mapping = {
            "cross-site scripting": "xss", "xss": "xss",
            "sql injection": "sqli",
            "server-side request forgery": "ssrf", "ssrf": "ssrf",
            "cross-site request forgery": "csrf", "csrf": "csrf",
            "code injection": "rce", "command injection": "rce",
            "remote code execution": "rce",
            "path traversal": "lfi", "file inclusion": "lfi",
            "xml external entit": "xxe",
            "open redirect": "open-redirect",
            "improper authentication": "auth-bypass",
            "privilege escalation": "privilege-escalation",
            "insecure direct object": "idor",
            "information disclosure": "information-disclosure",
            "information exposure": "information-disclosure",
            "business logic": "auth-bypass",
            "deserialization": "deserialization",
            "race condition": "race-condition",
        }
        for key, cat in mapping.items():
            if key in w:
                return cat
        # Slugify the weakness itself so it's at least a usable label.
        import re as _re
        return _re.sub(r"[^a-z0-9]+", "-", w).strip("-")[:30] or "misc"
