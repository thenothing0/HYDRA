"""GitHub source adapter — public Security Advisories (GHSA).

Uses the official GitHub REST API (https://api.github.com/advisories), which
serves the public Global Security Advisory database. No auth required, though
a token raises the rate limit and is used if provided (GITHUB_TOKEN).
"""

import logging
from typing import List

from hydra.ingest.base import (
    SourceAdapter, Writeup, register, classify_category, classify_severity,
)

logger = logging.getLogger("hydra.ingest.github")


@register
class GitHubAdvisoriesAdapter(SourceAdapter):
    name = "github"
    min_interval = 1.0
    API = "https://api.github.com/advisories"

    async def fetch(self, query: str = "", limit: int = 20) -> List[Writeup]:
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        # Paginate: GitHub caps per_page at 100, so walk pages to reach `limit`.
        from urllib.parse import quote
        raw: List[dict] = []
        page = 1
        while len(raw) < limit:
            per_page = min(100, limit - len(raw))
            url = (f"{self.API}?per_page={per_page}&page={page}"
                   f"&sort=published&direction=desc")
            if query:
                url += f"&query={quote(query)}"
            data = await self._get(url, headers=headers, as_json=True)
            if not isinstance(data, list) or not data:
                break
            raw.extend(data)
            if len(data) < per_page:
                break        # last page
            page += 1

        writeups: List[Writeup] = []
        for adv in raw[:limit]:
            summary = adv.get("summary", "") or ""
            description = adv.get("description", "") or ""
            text = f"{summary}\n\n{description}"
            sev = (adv.get("severity") or "").lower()
            if sev not in ("critical", "high", "medium", "low"):
                sev = classify_severity(text)
            # CWE names make good category hints
            cwe_text = " ".join(c.get("name", "") for c in adv.get("cwes", []))
            category = classify_category(f"{text} {cwe_text}")
            writeups.append(Writeup(
                source=self.name,
                title=summary or adv.get("ghsa_id", "advisory"),
                url=adv.get("html_url", adv.get("url", "")),
                content=text[:8000],
                category=category,
                severity=sev,
                author=adv.get("source_code_location", ""),
                published=adv.get("published_at", ""),
                tags=[adv.get("ghsa_id", "")] + [c.get("name", "") for c in adv.get("cwes", [])],
            ))
        logger.info(f"[github] fetched {len(writeups)} advisories")
        return writeups
