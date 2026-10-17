"""
╔══════════════════════════════════════════════════════════════╗
║  SafeProber — the ONLY component that sends a live payload.  ║
╚══════════════════════════════════════════════════════════════╝

Existing subprocess tools (httpx ``-silent``, ffuf's ``/FUZZ``) cannot inject a
chosen value into a single parameter and hand back a matchable body+status, so
the hunt engine needs one small, auditable HTTP primitive for detection-grade
active probing. Every guardrail HYDRA promises is enforced *here*, at the point
of transmission:

  * **Safe methods only (GET + bodyless OPTIONS), redirects disabled** — never
    mutates state. GET reads the raw ``Location`` header ourselves (open-redirect
    detection); the bodyless, non-mutating OPTIONS reads capability headers such
    as ``Allow`` (e.g. the dangerous-method / partial-PUT precondition) WITHOUT
    ever exercising a write verb. Neither carries a body; redirects stay off.
  * **Exploitation refused** — every URL is run through
    :func:`hydra.hunt.safety.is_exploitation_payload` first; a hit is dropped,
    not sent. The engine only ever feeds it curated benign probes anyway; this
    is the belt-and-braces second check.
  * **Scope-gated** — when an authorized scope is loaded, the target host must
    validate or the request is refused.
  * **Rate-limited** — a shared token bucket throttles every send.
  * **Bounded** — capped body read and a hard per-session request ceiling.
  * **Handshake / interim capture (bodyless)** — a separate primitive captures a
    response *status line* a normal request hides: a ``101 Switching Protocols``
    upgrade (WebSocket / h2c), or an interim ``100`` vs ``417`` reply to
    ``Expect: 100-continue``. It writes only the request line + ``Host`` +
    fail-closed-validated headers — **no body of any kind** — reads the status
    line(s) + header block, then CLOSES. It NEVER sends a WebSocket/HTTP-2 frame,
    NEVER completes or keeps the upgraded channel open, and uses only the safe,
    bodyless methods — it proves a *precondition*, never performs the exploit.

``fetch`` is injectable so the whole class runs offline in tests with no real
socket. Left ``None`` it lazily opens one aiohttp session.
"""

import inspect
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from hydra.hunt.safety import (
    is_exploitation_payload, sanitize_probe_headers, sanitize_auth_headers,
)

logger = logging.getLogger("hydra.hunt.prober")

# Only these safe, bodyless verbs may ever carry a handshake / interim-status
# capture. The upgrade (WebSocket/h2c) and Expect:100-continue preconditions are
# all GET; OPTIONS/HEAD are allowed as equally bodyless, non-mutating fallbacks.
# A write verb (PUT/DELETE/PATCH/POST) can never reach the handshake path.
_SAFE_HANDSHAKE_METHODS = frozenset({"GET", "OPTIONS", "HEAD"})


@dataclass
class ProbeResponse:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status != 0 and not self.error

    @property
    def location(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "location":
                return v
        return ""


@dataclass
class HandshakeResponse:
    """Result of one bodyless :meth:`SafeProber.handshake` status-line capture.

    ``codes`` is the source of truth: every ``HTTP/x.y CODE`` status code seen
    in order, so an interim ``100``/``103`` is preserved alongside a later final
    code and a terminal ``101`` is captured as-is. ``status`` is the last code
    (the final/terminal status). ``status_line`` is the raw first status line
    (useful verbatim evidence), ``reason`` the final status line's reason
    phrase, ``headers`` the fields of the last status-bearing block, and
    ``timed_out`` marks a connect/read with no status line (an Expect probe left
    waiting for a body we never send, or a dead socket). ``error`` carries a
    refusal or transport failure. The primitive NEVER sends a frame or keeps the
    channel open, so this object only ever describes a *precondition*.
    """
    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    codes: List[int] = field(default_factory=list)
    status_line: str = ""
    url: str = ""
    error: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.status != 0 and not self.error

    @property
    def switched(self) -> bool:
        """``101 Switching Protocols`` seen — the upgrade was ACCEPTED. We only
        captured the handshake status line and closed; the channel was never
        completed and no frame was ever sent."""
        return 101 in self.codes

    @property
    def saw_continue(self) -> bool:
        """An interim ``100 Continue`` was seen (``Expect: 100-continue`` honoured)."""
        return 100 in self.codes

    @property
    def expectation_failed(self) -> bool:
        """``417 Expectation Failed`` seen — the ``Expect`` was rejected."""
        return 417 in self.codes


def build_probe_url(base_url: str, param: str, value: str) -> str:
    """Return `base_url` with `param=value` merged into the query string."""
    parts = urlparse(base_url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != param]
    query.append((param, value))
    return urlunparse(parts._replace(query=urlencode(query)))


class SafeProber:
    """Benign, read-only (GET + bodyless OPTIONS), rate-limited, scope-gated
    HTTP probe primitive."""

    def __init__(self, scope_engine=None, rate_limiter=None,
                 fetch: Optional[Callable] = None, timeout: float = 10.0,
                 max_body: int = 8192, max_requests: int = 500,
                 handshake_fetch: Optional[Callable] = None):
        self.scope = scope_engine
        self.rate = rate_limiter
        self._fetch = fetch          # async fetch(url) -> (status, headers, body)
        # async handshake_fetch(url, headers, method) -> dict (offline test seam);
        # None → the real bodyless raw-socket capture in _raw_handshake.
        self._handshake_fetch = handshake_fetch
        self.timeout = timeout
        self.max_body = max_body
        self.max_requests = max_requests
        self._sent = 0
        self._session = None         # lazily-created aiohttp.ClientSession

    @property
    def sent(self) -> int:
        return self._sent

    def _scope_ok(self, url: str) -> bool:
        eng = self.scope
        if eng is None or not getattr(eng, "is_loaded", False):
            return True  # no authorized scope loaded → the caller's gate decides
        host = urlparse(url).hostname or url
        try:
            return bool(eng.validate_target(host).allowed)
        except Exception:  # pragma: no cover - defensive
            return False

    async def get(self, url: str,
                  headers: Optional[Dict[str, str]] = None,
                  credential_headers: Optional[Dict[str, str]] = None
                  ) -> ProbeResponse:
        """Perform one guarded GET. Never raises; refusals become an error resp.

        Optional benign ``headers`` (e.g. a detection-differential marker header
        such as CVE-2025-29927's ``x-middleware-subrequest``) are validated
        fail-closed via :func:`hydra.hunt.safety.sanitize_probe_headers` BEFORE
        transmission: if ANY header has a non-token name, a CR/LF/NUL (request
        splitting), or an exploitation-grade name/value, the WHOLE probe is
        refused — we never send a partially-sanitized header set.

        Optional ``credential_headers`` carry an opaque credential the operator
        already owns (a bearer token / API key for a target they are authorized
        against) and are validated via
        :func:`hydra.hunt.safety.sanitize_auth_headers` — same fail-closed
        name/CR-LF/NUL rules, but the credential VALUE is not run through the
        exploitation denylist (a real token may contain ``--``/``/*``; it is
        forwarded verbatim to the operator's own endpoint, never interpreted).
        Still GET-only, redirects-off, scope-gated and request-capped; if any
        credential header is unsafe the whole probe is refused.
        """
        return await self._guarded_send("GET", url, headers, credential_headers)

    async def options(self, url: str,
                      headers: Optional[Dict[str, str]] = None,
                      credential_headers: Optional[Dict[str, str]] = None
                      ) -> ProbeResponse:
        """Perform one guarded, bodyless, **non-mutating** OPTIONS request.

        OPTIONS is a safe method (RFC 9110 §9.3.1): it carries no body and never
        changes server state. HYDRA uses it ONLY to read capability-advertising
        response headers — chiefly ``Allow`` — so it can prove a *precondition*
        such as "a write method (PUT) is advertised on this path" (the
        CVE-2025-24813 Tomcat partial-PUT precondition) WITHOUT ever sending the
        write. It runs the SAME fail-closed gauntlet as :meth:`get`
        (request-cap → :func:`is_exploitation_payload` URL refusal → fail-closed
        header/credential sanitization → scope-gating → rate-limit →
        redirects-off) and returns the same :class:`ProbeResponse`; read the
        advertised methods from ``resp.headers``. HYDRA never follows an OPTIONS
        with a PUT/DELETE/PATCH — the dangerous method is observed as *advertised*,
        never *exercised*.
        """
        return await self._guarded_send("OPTIONS", url, headers,
                                        credential_headers)

    async def _run_guards(self, url: str,
                          headers: Optional[Dict[str, str]] = None,
                          credential_headers: Optional[Dict[str, str]] = None):
        """The shared fail-closed PRE-SEND gauntlet for every live primitive.

        Enforces, in this exact order, the hard request ceiling, the
        :func:`is_exploitation_payload` URL refusal, the fail-closed probe- and
        credential-header sanitizers, scope-gating and the shared rate limiter.
        On ANY refusal it returns ``(None, "<reason>")`` and NOTHING is sent or
        counted; on success it acquires a rate-limit token, increments the
        request counter and returns ``(safe_headers, None)``. Both
        :meth:`_guarded_send` (GET/bodyless OPTIONS) and :meth:`handshake`
        (bodyless interim/upgrade status-line capture) route through here, so no
        live primitive can ever diverge on — or slip past — a guardrail.
        """
        if self._sent >= self.max_requests:
            return None, "request cap reached"
        if is_exploitation_payload(url):
            logger.warning("refused exploitation-grade URL (never-exploit): %s", url)
            return None, "refused: exploitation payload"
        safe_headers: Optional[Dict[str, str]] = None
        if headers:
            safe_headers, rejected = sanitize_probe_headers(headers)
            if rejected:
                logger.warning(
                    "refused unsafe probe header(s) (never-exploit): %s",
                    ", ".join(rejected))
                return None, f"refused: unsafe header(s) {rejected}"
        if credential_headers:
            safe_auth, rejected_auth = sanitize_auth_headers(credential_headers)
            if rejected_auth:
                logger.warning(
                    "refused unsafe credential header(s): %s",
                    ", ".join(rejected_auth))
                return None, f"refused: unsafe credential header(s) {rejected_auth}"
            safe_headers = {**(safe_headers or {}), **safe_auth}
        if not self._scope_ok(url):
            return None, "refused: out of scope"
        if self.rate is not None:
            try:
                await self.rate.wait_and_acquire()
            except Exception:
                await self.rate.acquire()
        self._sent += 1
        return safe_headers, None

    async def _guarded_send(self, method: str, url: str,
                            headers: Optional[Dict[str, str]] = None,
                            credential_headers: Optional[Dict[str, str]] = None
                            ) -> ProbeResponse:
        """Shared fail-closed send gauntlet behind :meth:`get`/:meth:`options`.

        ``method`` is restricted by its only two callers to the safe, non-mutating
        verbs ``GET`` and bodyless ``OPTIONS`` — no body is ever attached and
        redirects stay off, so neither verb can mutate target state. The whole
        guardrail chain (request ceiling, :func:`is_exploitation_payload` URL
        refusal, fail-closed header/credential sanitizers, scope-gating and the
        shared rate limiter) runs in :meth:`_run_guards`, so OPTIONS can never
        slip past a check GET is subject to. Never raises; a refusal becomes a
        ProbeResponse carrying ``error``.
        """
        safe_headers, error = await self._run_guards(
            url, headers, credential_headers)
        if error is not None:
            return ProbeResponse(url=url, error=error)
        try:
            status, resp_headers, body = await self._do_fetch(
                url, safe_headers, method)
        except Exception as e:
            return ProbeResponse(url=url, error=str(e))
        return ProbeResponse(status=status, headers=dict(resp_headers or {}),
                             body=(body or "")[:self.max_body], url=url)

    async def probe_param(self, base_url: str, param: str, value: str,
                          headers: Optional[Dict[str, str]] = None
                          ) -> ProbeResponse:
        """GET `base_url` with a single benign `param=value` merged in."""
        return await self.get(build_probe_url(base_url, param, value),
                              headers=headers)

    async def handshake(self, url: str,
                        headers: Optional[Dict[str, str]] = None,
                        credential_headers: Optional[Dict[str, str]] = None,
                        method: str = "GET") -> HandshakeResponse:
        """One guarded, BODYLESS handshake / interim status-line capture.

        A few detection PRECONDITIONS live in the response *status line* a normal
        request abstracts away: a WebSocket/h2c ``Upgrade`` returns ``101
        Switching Protocols`` (a foreign benign ``Origin`` still 101'ing is the
        CSWSH precondition — the server never validated it); an
        ``Expect: 100-continue`` returns an interim ``100`` vs a ``417`` vs a
        final ``200`` (the Expect-based CL.0 desync precondition). This primitive
        opens a connection, writes ONLY the request line + ``Host`` +
        fail-closed-validated headers — **no body of any kind** — reads the
        response status line(s) + header block, then **CLOSES immediately**.

        Never-exploit boundary, enforced structurally: it NEVER sends a WebSocket
        or HTTP/2 frame, NEVER completes or keeps the upgraded channel open,
        NEVER writes a request body, and accepts only the safe bodyless methods
        (:data:`_SAFE_HANDSHAKE_METHODS`). It runs the IDENTICAL fail-closed
        gauntlet as :meth:`get`/:meth:`options` via :meth:`_run_guards`
        (request-cap → :func:`is_exploitation_payload` URL refusal → fail-closed
        header/credential sanitization → scope-gating → rate-limit). Evidence
        from it caps at OBSERVED — it proves a precondition, never an exploit.
        Never raises; a refusal/transport error becomes a
        :class:`HandshakeResponse` carrying ``error``.
        """
        verb = (method or "GET").upper()
        if verb not in _SAFE_HANDSHAKE_METHODS:
            return HandshakeResponse(
                url=url, error=f"refused: unsafe handshake method {method}")
        safe_headers, error = await self._run_guards(
            url, headers, credential_headers)
        if error is not None:
            return HandshakeResponse(url=url, error=error)
        try:
            data = await self._do_handshake(url, safe_headers, verb)
        except Exception as e:  # never raises out of the primitive
            return HandshakeResponse(url=url, error=str(e))
        if data.get("error"):
            return HandshakeResponse(url=url, error=str(data["error"]),
                                     timed_out=bool(data.get("timed_out")))
        codes = [int(c) for c in (data.get("codes") or [])]
        return HandshakeResponse(
            status=(codes[-1] if codes else 0),
            reason=str(data.get("reason", "")),
            headers=dict(data.get("headers") or {}),
            codes=codes,
            status_line=str(data.get("status_line", "")),
            url=url,
            timed_out=bool(data.get("timed_out")),
        )

    # __HANDSHAKE_HELPERS__

    async def _do_handshake(self, url: str,
                            headers: Optional[Dict[str, str]] = None,
                            method: str = "GET"):
        """Dispatch to the injected handshake fake (offline tests) or the real
        bodyless raw-socket capture. The fake is called
        ``handshake_fetch(url, headers, method)`` and returns a dict with any of
        ``codes`` (List[int]), ``status_line``, ``reason``, ``headers``,
        ``timed_out``, ``error``."""
        if self._handshake_fetch is not None:
            return await self._handshake_fetch(url, headers or {}, method)
        return await self._raw_handshake(url, headers or {}, method)

    async def _raw_handshake(self, url: str, headers: Dict[str, str],
                             method: str):
        """REAL bodyless capture: open a TCP/TLS connection, write exactly the
        request line + ``Host`` + validated headers + CRLFCRLF (NO body), read
        only the status line(s) + header block, then CLOSE. It writes nothing
        after the header block — no request body, no WebSocket/HTTP-2 frame, no
        upgrade payload — and never keeps the socket open."""
        import asyncio
        import ssl as _ssl
        parts = urlparse(url)
        host = parts.hostname
        if not host:
            return {"error": "refused: no host in url"}
        secure = parts.scheme == "https"
        port = parts.port or (443 if secure else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        ssl_ctx = _ssl.create_default_context() if secure else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.timeout)
        except Exception as e:
            return {"error": f"connect failed: {e}"}
        try:
            # Host is taken from the URL and never duplicated/overridden.
            lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
            for k, v in (headers or {}).items():
                if str(k).lower() == "host":
                    continue
                lines.append(f"{k}: {v}")
            # Bodyless by construction: terminate the header block and send
            # NOTHING further — no body, no WS/h2 frame, no upgrade payload.
            request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            try:
                raw = await asyncio.wait_for(
                    reader.read(self.max_body), timeout=self.timeout)
            except asyncio.TimeoutError:
                return {"timed_out": True}
            parsed = self._parse_status_lines(
                raw.decode("latin-1", "replace") if raw else "")
            if not parsed.get("codes"):
                parsed["timed_out"] = True  # no status line read → treat as timeout
            return parsed
        finally:
            # Close immediately — the channel is never upgraded or kept open.
            try:
                writer.close()
            except Exception:  # pragma: no cover - defensive
                pass

    @staticmethod
    def _parse_status_lines(text: str):
        """Parse every ``HTTP/x.y CODE REASON`` status line in a raw response head.

        Returns ``{"codes", "status_line", "reason", "headers"}``: ``codes`` is
        every status code in order (an interim ``100``/``103`` preserved beside a
        later final code, a terminal ``101`` captured as-is), ``status_line`` the
        first raw status line, ``reason`` the LAST status line's reason phrase,
        and ``headers`` the fields of the LAST status-bearing block. Tolerant of
        bare ``\\n`` block separators."""
        codes: List[int] = []
        status_line = ""
        reason = ""
        headers: Dict[str, str] = {}
        for block in re.split(r"\r?\n\r?\n", text or ""):
            block_lines = block.split("\n")
            first = block_lines[0].strip() if block_lines else ""
            m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$", first)
            if not m:
                continue
            if not status_line:
                status_line = first
            codes.append(int(m.group(1)))
            reason = (m.group(2) or "").strip()
            hdrs: Dict[str, str] = {}
            for ln in block_lines[1:]:
                ln = ln.strip()
                if not ln or ":" not in ln:
                    continue
                key, _, val = ln.partition(":")
                key = key.strip()
                if key:
                    hdrs[key] = val.strip()
            headers = hdrs
        return {"codes": codes, "status_line": status_line,
                "reason": reason, "headers": headers}

    def _fetch_arity(self) -> int:
        """Positional-arg count the injected ``fetch`` accepts (``*args`` → 3).

        Lets :meth:`_do_fetch` pick the richest call a fake supports —
        ``fetch(url, headers, method)`` on a method-aware arity-3 fake,
        ``fetch(url, headers)`` on a header-aware 2-arg fake, or the legacy
        one-arg ``fetch(url)`` — without ever changing an existing fake's call
        shape. A fetch we cannot introspect falls back to the 1-arg legacy call.
        """
        fn = self._fetch
        target = fn if (inspect.isfunction(fn) or inspect.ismethod(fn)) \
            else getattr(fn, "__call__", fn)
        try:
            params = inspect.signature(target).parameters.values()
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return 1
        positional = 0
        for p in params:
            if p.kind is inspect.Parameter.VAR_POSITIONAL:
                return 3
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                          inspect.Parameter.POSITIONAL_OR_KEYWORD):
                positional += 1
        return positional

    def _fetch_accepts_headers(self) -> bool:
        """True if the injected ``fetch`` accepts a 2nd (headers) positional arg.

        Lets a header-aware probe call ``fetch(url, headers)`` on a modern
        fetch while legacy ``fetch(url)`` fakes (every existing test) keep their
        exact one-arg call signature — no double-send, decided by inspection.
        """
        return self._fetch_arity() >= 2

    async def _do_fetch(self, url: str,
                        headers: Optional[Dict[str, str]] = None,
                        method: str = "GET"):
        if self._fetch is not None:
            # Backward-compatible dispatch by the fake's positional arity: a
            # method-aware fetch(url, headers, method) gets the verb, a
            # header-aware fetch(url, headers) gets the headers, and a legacy
            # fetch(url) fake keeps its exact one-arg call — no double-send.
            arity = self._fetch_arity()
            if arity >= 3:
                return await self._fetch(url, headers, method)
            if headers and arity >= 2:
                return await self._fetch(url, headers)
            return await self._fetch(url)
        import aiohttp  # imported lazily so offline tests need no network stack
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout))
        # ``request`` carries the safe verb (GET or bodyless OPTIONS) with no
        # body and redirects off; it never issues a write method.
        async with self._session.request(method, url, allow_redirects=False,
                                         headers=headers or None) as resp:
            body = await resp.content.read(self.max_body)
            return resp.status, dict(resp.headers), body.decode("utf-8", "replace")

    async def close(self):
        if self._session is not None:
            await self._session.close()
            self._session = None
