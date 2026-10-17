"""Medium source adapter — public RSS feeds.

Medium exposes RSS for tags (medium.com/feed/tag/<tag>). This adapter pulls
public write-up articles and normalises them. RSS is a published, ToS-friendly
interface; we only read summaries/content Medium chooses to syndicate.
"""

import logging
import re
from typing import List
from urllib.parse import quote

from hydra.ingest.base import (
    SourceAdapter, Writeup, register, classify_category, classify_severity,
)

logger = logging.getLogger("hydra.ingest.medium")


@register
class MediumAdapter(SourceAdapter):
    name = "medium"
    min_interval = 2.0
    FEED = "https://medium.com/feed/tag/{tag}"

    # Related security tags used to fan out when a large limit is requested,
    # since each Medium RSS feed only returns the latest ~10 items per tag.
    RELATED_TAGS = [
        "bug-bounty", "cybersecurity", "penetration-testing", "infosec",
        "hacking", "web-security", "vulnerability", "ethical-hacking",
        "security-research", "appsec", "xss", "sql-injection", "ssrf",
        "bug-bounty-tips", "bug-bounty-writeup",
    ]

    async def fetch(self, query: str = "", limit: int = 20) -> List[Writeup]:
        # Build the tag list: the requested tag first, then related tags if we
        # need more than one feed's worth to approach `limit`.
        primary = (query or "bug-bounty").strip().lower().replace(" ", "-")
        tags = [primary]
        if limit > 10:
            tags += [t for t in self.RELATED_TAGS if t != primary]

        seen: set = set()
        out: List[Writeup] = []
        for tag in tags:
            if len(out) >= limit:
                break
            url = self.FEED.format(tag=quote(tag))
            xml = await self._get(url, headers={"Accept": "application/rss+xml"})
            if not xml:
                continue
            for w in self._parse_rss(xml, limit):
                if w.url in seen:
                    continue
                seen.add(w.url)
                out.append(w)
                if len(out) >= limit:
                    break
        logger.info(f"[medium] fetched {len(out)} articles across {len(tags)} tag(s)")
        return out[:limit]

    def _parse_rss(self, xml: str, limit: int) -> List[Writeup]:
        writeups: List[Writeup] = []
        # Each <item> is one article. Regex is sufficient for RSS and avoids
        # an XML dependency; fields are CDATA-wrapped by Medium.
        items = re.findall(r"(?s)<item>(.*?)</item>", xml)
        for item in items[:limit]:
            title = self._tag(item, "title")
            link = self._tag(item, "link")
            author = self._tag(item, "dc:creator")
            pub = self._tag(item, "pubDate")
            raw = self._tag(item, "content:encoded") or self._tag(item, "description")
            categories = re.findall(r"<category>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</category>", item)
            content = self._strip_html(raw)
            if not title or not link:
                continue
            text = f"{title} {' '.join(categories)} {content}"
            writeups.append(Writeup(
                source=self.name,
                title=title,
                url=link,
                content=content[:8000],
                category=classify_category(text),
                severity=classify_severity(text),
                author=author,
                published=pub,
                tags=categories,
            ))
        logger.info(f"[medium] fetched {len(writeups)} articles")
        return writeups

    @staticmethod
    def _tag(block: str, tag: str) -> str:
        m = re.search(rf"(?s)<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", block)
        if not m:
            return ""
        val = m.group(1)
        cdata = re.match(r"(?s)\s*<!\[CDATA\[(.*?)\]\]>\s*$", val)
        return (cdata.group(1) if cdata else val).strip()
