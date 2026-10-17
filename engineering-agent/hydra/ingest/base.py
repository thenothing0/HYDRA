"""Base types and registry for write-up source adapters."""

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger("hydra.ingest")

USER_AGENT = "HYDRA-Research/3.0 (+security writeup ingest; contact: local)"

# Vulnerability categories we try to tag write-ups with.
VULN_CATEGORIES = [
    "ssrf", "xss", "sqli", "idor", "rce", "lfi", "ssti", "xxe", "csrf",
    "oauth", "cors", "open-redirect", "auth-bypass", "privilege-escalation",
    "reentrancy", "race-condition", "deserialization", "prototype-pollution",
    "subdomain-takeover", "information-disclosure",
]

_CATEGORY_HINTS = {
    "sqli": ["sql injection", "sqli", "blind sql"],
    "xss": ["xss", "cross-site scripting", "cross site scripting"],
    "ssrf": ["ssrf", "server-side request", "server side request"],
    "idor": ["idor", "insecure direct object", "bola", "broken object level"],
    "rce": ["rce", "remote code execution", "command injection"],
    "lfi": ["lfi", "local file inclusion", "path traversal"],
    "ssti": ["ssti", "template injection"],
    "xxe": ["xxe", "xml external entity"],
    "csrf": ["csrf", "cross-site request forgery"],
    "oauth": ["oauth", "openid"],
    "cors": ["cors misconfig", "cross-origin"],
    "open-redirect": ["open redirect"],
    "auth-bypass": ["auth bypass", "authentication bypass", "broken authentication"],
    "privilege-escalation": ["privilege escalation", "privesc", "idor to admin"],
    "reentrancy": ["reentrancy", "reentrant"],
    "race-condition": ["race condition", "toctou"],
    "deserialization": ["insecure deserialization", "deserialization"],
    "prototype-pollution": ["prototype pollution"],
    "subdomain-takeover": ["subdomain takeover"],
    "information-disclosure": ["information disclosure", "info leak", "data exposure"],
}


@dataclass
class Writeup:
    """A normalised, source-agnostic security write-up."""
    source: str
    title: str
    url: str
    content: str = ""
    category: str = "misc"
    severity: str = "medium"
    author: str = ""
    published: str = ""
    tags: List[str] = field(default_factory=list)
    fetched_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def doc_id(self) -> str:
        import hashlib
        return hashlib.sha1(f"{self.source}|{self.url}".encode()).hexdigest()[:16]


def classify_category(text: str) -> str:
    """Best-effort vulnerability category from free text."""
    t = (text or "").lower()
    best, best_hits = "misc", 0
    for cat, hints in _CATEGORY_HINTS.items():
        hits = sum(t.count(h) for h in hints)
        if hits > best_hits:
            best, best_hits = cat, hits
    return best


def classify_severity(text: str) -> str:
    t = (text or "").lower()
    for sev in ("critical", "high", "medium", "low"):
        if sev in t:
            return sev
    return "medium"


class RateLimiter:
    """Simple async min-interval limiter (per adapter)."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class SourceAdapter(ABC):
    """Base class for a write-up source. Subclass + @register to add one."""

    name: str = "base"
    #: minimum seconds between requests to this source
    min_interval: float = 1.0

    def __init__(self, token: str = ""):
        self.token = token
        self._rl = RateLimiter(self.min_interval)

    @abstractmethod
    async def fetch(self, query: str = "", limit: int = 20) -> List[Writeup]:
        """Fetch up to `limit` write-ups matching `query`."""
        ...

    # ── shared HTTP helpers ────────────────────
    @staticmethod
    def _make_session(timeout_total: float):
        """Create an aiohttp session that resolves DNS reliably.

        aiohttp's default async resolver fails on some Windows setups
        ("Could not contact DNS servers"); ThreadedResolver uses the OS
        resolver and works everywhere. family=0 allows both IPv4/IPv6.
        """
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=timeout_total)
        try:
            connector = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver(),
                                             family=0)
            return aiohttp.ClientSession(timeout=timeout, connector=connector)
        except Exception:
            # Fall back to a plain session if the connector can't be built.
            return aiohttp.ClientSession(timeout=timeout)

    async def _get(self, url: str, headers: Optional[Dict] = None,
                   as_json: bool = False) -> Optional[Any]:
        await self._rl.wait()
        try:
            import aiohttp  # noqa: F401
        except Exception:
            logger.error("aiohttp not installed — cannot fetch")
            return None
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        try:
            async with self._make_session(30) as s:
                async with s.get(url, headers=hdrs) as r:
                    if r.status != 200:
                        logger.warning(f"[{self.name}] GET {url} → HTTP {r.status}")
                        return None
                    return await (r.json() if as_json else r.text())
        except Exception as e:
            logger.warning(f"[{self.name}] fetch failed ({url}): {e}")
            return None

    async def _post_json(self, url: str, payload: Dict[str, Any],
                         headers: Optional[Dict] = None,
                         retries: int = 3) -> Optional[Any]:
        """POST JSON and parse a JSON response, with rate limiting + backoff."""
        try:
            import aiohttp  # noqa: F401
        except Exception:
            logger.error("aiohttp not installed — cannot fetch")
            return None
        hdrs = {"User-Agent": USER_AGENT, "Content-Type": "application/json",
                "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        for attempt in range(retries):
            await self._rl.wait()
            try:
                async with self._make_session(45) as s:
                    async with s.post(url, json=payload, headers=hdrs) as r:
                        if r.status == 200:
                            return await r.json()
                        if r.status in (429, 502, 503):
                            wait = 2 ** attempt
                            logger.warning(f"[{self.name}] POST {url} → HTTP {r.status}, "
                                           f"retry in {wait}s")
                            await asyncio.sleep(wait)
                            continue
                        logger.warning(f"[{self.name}] POST {url} → HTTP {r.status}")
                        return None
            except Exception as e:
                logger.warning(f"[{self.name}] POST failed ({url}): {e}")
                await asyncio.sleep(2 ** attempt)
        return None

    @staticmethod
    def _strip_html(html: str) -> str:
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = re.sub(r"&[a-z]+;", " ", text)
        return re.sub(r"\s+", " ", text).strip()


# ── Registry ───────────────────────────────────
REGISTRY: Dict[str, Type[SourceAdapter]] = {}


def register(cls: Type[SourceAdapter]) -> Type[SourceAdapter]:
    """Class decorator to register a source adapter by its `name`."""
    REGISTRY[cls.name] = cls
    return cls
