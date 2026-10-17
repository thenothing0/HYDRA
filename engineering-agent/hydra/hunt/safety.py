"""
╔══════════════════════════════════════════════════════════════╗
║  Hunt Safety — payload allowlist + benign detection probes  ║
║  Enforces HYDRA's never-exploit doctrine at the send point. ║
╚══════════════════════════════════════════════════════════════╝

The hunt engine may *actively probe* a target when the operator opts in
(``--hunt-active``). Active probing is strictly **detection-grade**: we send
benign, non-destructive values that reveal whether a class of weakness is
*present*, and we NEVER send a payload that would exploit it (no RCE, no data
exfiltration, no OOB, no auth bypass, no destructive SQL, no executable XSS).

This module is the single choke point for that rule:

  * ``is_exploitation_payload()`` — a defense-in-depth denylist. The prober
    refuses to transmit anything it flags, so even a mis-curated strategy can
    never turn into a live exploit.
  * ``BENIGN_PROBES`` / ``benign_probes_for()`` — the curated, detection-only
    probes the engine is actually allowed to send, one small set per class.
  * ``EvidenceLevel`` — the doctrine's evidence ladder, attached to every
    finding so a report never overstates what was proven.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import quote, unquote


class EvidenceLevel:
    """Doctrine evidence ladder (CLAUDE.md §Evidence Integrity).

    OBSERVED   — we directly saw the behaviour (e.g. path returns 200).
    REPRODUCED — we triggered it more than once / with a controlled differential.
    INFERRED   — deduced from a signal (error string, arithmetic evaluation).
    UNVERIFIED — a lead only (e.g. reflection ≠ proven execution).
    """
    OBSERVED = "observed"
    REPRODUCED = "reproduced"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


# ── Exploitation denylist ──────────────────────
# Case-insensitive substrings that mark a payload as exploitation-grade. If any
# appears, the prober refuses to send it. These cover RCE/template escapes,
# time/boolean/union SQLi, SSRF pivots to internal & cloud-metadata hosts,
# path traversal, and executable/redirecting XSS. Benign detection probes
# (arithmetic `{{7*7}}`, a bare quote, an `example.com` canary, a non-exec
# reflection marker) are deliberately NOT matched here.
EXPLOITATION_MARKERS: List[str] = [
    # code / template execution
    "popen", "__globals__", "__subclasses__", "__mro__", "__import__",
    "__class__", "__class", "__builtins__", "subprocess", "runtime",
    "forname(", ".forname", "getruntime", "getclass(", "processbuilder",
    "t(java", "lipsum", "eval(", "system(", "exec(", "constructor.constructor",
    # SQL injection (destructive / extractive / blind)
    "union select", "or 1=1", "or '1'='1", 'or "1"="1', "'='", "waitfor",
    "sleep(", "benchmark(", "pg_sleep", "dbms_pipe", "; drop", "; select",
    "--", "/*", "xp_cmdshell",
    # SSRF pivots — internal, loopback, cloud metadata
    "file://", "gopher://", "dict://", "ldap://", "127.0.0.1", "localhost",
    "[::1]", "0x7f000001", "2130706433", "0177.0.0.1", "169.254.169.254",
    "metadata.google", "100.100.100.200", "computemetadata",
    # path / file traversal
    "../", "..\\", "..%2f", "..%5c", "/etc/passwd", "etc/passwd", "win.ini",
    "boot.ini", "/proc/self",
    # executable / redirecting XSS + dangerous schemes
    "<script", "javascript:", "data:text/html", "srcdoc", "onerror",
    "onload", "onfocus", "ontoggle", "onmouseover", "alert(", "prompt(",
    "document.cookie", "document.domain", "fetch(", "<iframe", "<svg",
    "<img",
]

# Regex-based exploitation signals for gadgets a plain substring cannot pin down
# without false-positives on ordinary words. Kept tight so they fire on code, not
# prose: a Java constructor of a *qualified* type (``new java.lang.ProcessBuilder``)
# and a SpEL/OGNL type reference (``T(org.x.Y)`` / ``T(java.lang.Runtime)``).
_EXPLOITATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bnew\s+[\w$]+(?:\.[\w$]+)+", re.IGNORECASE),   # new a.b.C(...)
    re.compile(r"\bt\(\s*['\"]?[\w$]+(?:\.[\w$]+)+", re.IGNORECASE),  # T(a.b.C)
]


# ── WorstFit / Unicode look-alike folding (enabler #7) ──
# A Windows code-page "best-fit" transform (the CVE-2024-4577 / WorstFit class)
# silently maps many Unicode look-alikes onto dangerous ASCII bytes AFTER our
# denylist would have run — e.g. U+FF0F '／' → '/', U+00AD soft-hyphen → '-'
# (php-cgi ``?%ADv`` → ``-v`` arg injection), U+00A5 '¥' → '\'. We fold those
# forms here so an *obfuscated* traversal / quote / arg-injection is unmasked
# BEFORE ``is_exploitation_payload`` inspects it. Folding can never make a benign
# value harmful — it only reveals a harmful one hidden behind a look-alike.
_BESTFIT_FOLD: Dict[str, str] = {
    "­": "-",   # soft hyphen        → '-'
    "¥": "\\",  # yen sign           → '\'  (CP932 best-fit)
    "₩": "\\",  # won sign           → '\'
    "¦": "|",   # broken bar         → '|'
    "‘": "'", "’": "'", "‛": "'",   # curly single quotes → '
    "“": '"', "”": '"', "‟": '"',   # curly double quotes → "
    "‐": "-", "‑": "-", "‒": "-",
    "–": "-", "—": "-", "―": "-",    # unicode hyphens/dashes → -
    "⁄": "/",   # fraction slash     → '/'
    "∕": "/",   # division slash     → '/'
    "∖": "\\",  # set-minus operator → '\'
}

# Zero-width / invisible separators used to split a token past a substring
# denylist (``..​/`` should collapse to ``../``). Stripped before folding.
_INVISIBLE: Tuple[str, ...] = (
    "​", "‌", "‍", "⁠", "﻿", " ",
    "᠎", "‎", "‏",
)


def _fold_unicode(s: str) -> str:
    """Fold Unicode look-alikes / invisibles to their ASCII equivalents.

      * NFKC folds fullwidth & compatibility forms (U+FF0F '／' → '/',
        U+FF02 '＂' → '"', U+FF3C → '\\', fullwidth digits/letters/braces).
      * ``_BESTFIT_FOLD`` handles the Windows best-fit look-alikes NFKC leaves
        alone (soft-hyphen → '-', yen/won → '\\', curly quotes, unicode dashes).
      * invisible/zero-width separators are removed so they cannot split a token.

    Defense-in-depth only (used by ``_normalize``): never turns a benign value
    harmful, only unmasks an obfuscated harmful one.
    """
    if not s:
        return s
    for ch in _INVISIBLE:
        if ch in s:
            s = s.replace(ch, "")
    s = unicodedata.normalize("NFKC", s)
    if any(ch in _BESTFIT_FOLD for ch in s):
        s = "".join(_BESTFIT_FOLD.get(ch, ch) for ch in s)
    return s


def _normalize(payload: str) -> str:
    """Fold common WAF-bypass encodings so an *obfuscated* exploit is still
    caught by the denylist. This is defense-in-depth ONLY — it can never turn a
    benign value harmful, it only unmasks a harmful one hidden behind encoding.

      * percent-decode up to 3 layers (single/double/triple URL-encoding),
      * fold Unicode look-alikes / best-fit forms / invisibles to ASCII
        (``_fold_unicode`` — U+FF0F '／' → '/', soft-hyphen → '-', …),
      * lowercase,
      * collapse SQL inline comments (``/**/``, ``/*!``) used to split keywords,
      * drop backticks / whitespace tricks used to break up tokens.
    """
    s = str(payload)
    for _ in range(3):                     # peel nested percent-encoding
        d = unquote(s)
        if d == s:
            break
        s = d
    s = _fold_unicode(s)                   # WorstFit / look-alike → ASCII
    s = s.lower()
    for tok in ("/**/", "/*!", "*/", "/*"):
        s = s.replace(tok, " ")
    for ch in ("`", "\n", "\t", "\r"):
        s = s.replace(ch, " ")
    return s


def is_exploitation_payload(payload: str) -> bool:
    """Return True if `payload` looks exploitation-grade and must NOT be sent.

    Defense-in-depth: the curated benign probes below all return False here;
    every exploitation payload in ``strategies.py`` returns True. The prober
    calls this on every value before transmission.

    The check runs against BOTH the raw lowercased value and a decoded/de-obfuscated
    form, so an encoded harmful payload (e.g. ``%27%20OR%201=1``,
    ``union/**/select``, ``..%252fetc%252fpasswd``) is blocked just like its
    plain form — while encoded *benign* probes (which decode back to a harmless
    value) still pass.
    """
    if not payload:
        return False
    raw = str(payload).lower()
    norm = _normalize(payload)
    if any(m in raw or m in norm for m in EXPLOITATION_MARKERS):
        return True
    return any(p.search(raw) or p.search(norm) for p in _EXPLOITATION_PATTERNS)


# ── Request-header probe safety ────────────────
# A few detection differentials need a benign REQUEST HEADER rather than a query
# parameter. The canonical case is CVE-2025-29927 (Next.js middleware bypass):
# the mere PRESENCE of ``x-middleware-subrequest`` flips a protected route's
# status, so we detect it with a header A/B differential — never by reading the
# gated content. The same never-exploit denylist applies to header names AND
# values, plus one rule query strings don't need: a CR/LF/NUL would SPLIT the
# request (header injection / request smuggling), so those are refused too.
# Every check here is fail-closed.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")  # RFC 7230 token
_HEADER_FORBIDDEN = ("\r", "\n", "\x00")


def _has_forbidden_char(s: str) -> bool:
    """True if a header name/value carries CR/LF/NUL — raw OR percent-decoded.

    Decoding first means an encoded ``%0d%0a`` cannot smuggle a line break past
    us and split the request downstream. Defense-in-depth only.
    """
    s = str(s)
    seen = [s]
    dec = s
    for _ in range(3):                      # peel nested percent-encoding
        nxt = unquote(dec)
        if nxt == dec:
            break
        dec = nxt
        seen.append(dec)
    return any(ch in cand for cand in seen for ch in _HEADER_FORBIDDEN)


def is_safe_probe_header(name: str, value: str) -> bool:
    """Return True only if a single request header is safe to transmit.

    Fail-closed. A header is safe iff ALL hold:
      * ``name`` is a non-empty RFC 7230 token (no spaces / colons / controls),
      * neither name nor value contains CR/LF/NUL, raw or percent-decoded — so
        it can never split the request (no smuggling / header injection),
      * neither name nor value is exploitation-grade
        (:func:`is_exploitation_payload`) — a header may carry a benign
        differential marker, never an RCE/SSRF/traversal/exec payload.
    """
    if not name or not isinstance(name, str):
        return False
    if not _HEADER_NAME_RE.match(name):
        return False
    val = "" if value is None else str(value)
    if _has_forbidden_char(name) or _has_forbidden_char(val):
        return False
    if is_exploitation_payload(name) or is_exploitation_payload(val):
        return False
    return True


def sanitize_probe_headers(headers) -> Tuple[Dict[str, str], List[str]]:
    """Split a header mapping into ``(safe_dict, rejected_names)``.

    Each header is validated with :func:`is_safe_probe_header`. Safe ones are
    returned in a clean dict (values coerced to ``str``); the *names* of any
    rejected ones are collected so the caller can fail-closed and log exactly
    what was dropped. Order-preserving; a ``None``/empty mapping → ``({}, [])``.
    """
    safe: Dict[str, str] = {}
    rejected: List[str] = []
    for name, value in (headers or {}).items():
        if is_safe_probe_header(name, value):
            safe[str(name)] = "" if value is None else str(value)
        else:
            rejected.append(str(name))
    return safe, rejected


def sanitize_auth_headers(headers) -> Tuple[Dict[str, str], List[str]]:
    """Split a CREDENTIAL header mapping into ``(safe_dict, rejected_names)``.

    This is the ONLY place HYDRA relaxes :func:`sanitize_probe_headers`, and it
    relaxes it on exactly one axis: the header *value* is an opaque credential
    the operator already owns (a bearer token / API key for a target they are
    authorized against), so the value is **not** run through
    :func:`is_exploitation_payload`. A legitimate token can contain substrings
    that merely look like SQL/exec markers (``--``, ``/*``, base64 ``==``
    padding); dropping it would defeat an authorized secret-overshare check
    (P5 / CVE-2025-59363) without preventing any real attack — the value is sent
    verbatim to the operator's own endpoint, never interpreted by HYDRA.

    Everything that could actually turn a header into an *attack* is still
    enforced, fail-closed, on BOTH name and value:
      * the name must be a non-empty RFC-7230 token,
      * the name must not be exploitation-grade (a header *name* is never a
        credential, so there is no reason to relax it),
      * neither name nor value may contain CR/LF/NUL — raw OR percent-decoded —
        so a credential header can never split the request / smuggle a second
        one (the one threat that matters on a GET).

    HYDRA never authenticates *with* or stores the credential; it forwards it
    once, GET-only, to the in-scope target, and reads the response only to the
    REDACTED, value-free degree :func:`scan_body_for_secrets` allows.
    """
    safe: Dict[str, str] = {}
    rejected: List[str] = []
    for name, value in (headers or {}).items():
        n = "" if name is None else str(name)
        val = "" if value is None else str(value)
        ok = (bool(n) and bool(_HEADER_NAME_RE.match(n))
              and not _has_forbidden_char(n) and not _has_forbidden_char(val)
              and not is_exploitation_payload(n))
        if ok:
            safe[n] = val
        else:
            rejected.append(n)
    return safe, rejected


# ── enabler #5: secret KEY-presence detection + VALUE redaction ──
# The "proof without exfiltration" primitive. An authorized info-disclosure
# check (RabbitMQ management OAuth leak / OneLogin OIDC overshare) must be able
# to prove a response EXPOSES a credential without ever reading, storing, or
# echoing the credential VALUE. These helpers detect a sensitive key by NAME,
# confirm the value is actually populated (not a placeholder), and emit only
# non-reversible facts: the key name, its path, the value LENGTH, and a salted
# fingerprint. The value itself never leaves this module.
SECRET_KEY_TOKENS: Tuple[str, ...] = (
    "apikey", "secretkey", "secretaccesskey", "awssecretaccesskey",
    "privatekey", "signingkey", "encryptionkey", "accesstoken",
    "refreshtoken", "sessiontoken", "bearertoken", "authtoken",
    "clientsecret", "oauthclientsecret", "password", "passwd", "passphrase",
    "connectionstring",
)

# Obvious non-secrets: an empty/sentinel/placeholder value is a non-finding and
# must not be flagged (keeps false positives out; never inspects value meaning).
_SECRET_PLACEHOLDER_RE = re.compile(
    r"^(?:null|none|nil|undefined|changeme|change[-_ ]?me|placeholder|redacted|"
    r"x{3,}|\*+|\.{3,}|-+|your[-_ ]?secret[-_ ]?here|<[^>]*>|example|sample|"
    r"test|dummy|foo|bar|n/?a)$",
    re.IGNORECASE)

_SECRET_FP_SALT = "hydra-secret-fp::"

# Bounded "key":"value" fallback for a body that is near-JSON but not parseable.
_SECRET_JSON_PAIR_RE = re.compile(
    r'"([A-Za-z0-9_.\-]{1,64})"\s*:\s*"((?:[^"\\]|\\.){1,4096})"')


def _normalize_key(key) -> str:
    """Lowercase a key name and strip every non-alphanumeric char, so
    ``client_secret``, ``clientSecret`` and ``client-secret`` all compare equal.
    """
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_secret_key(key) -> bool:
    """True if a JSON/form key NAME denotes a credential whose VALUE must never
    be read or echoed — only its presence reported. Name-only; value-blind.

    Matches a key that ends with ``secret`` (``client_secret``,
    ``oauth_client_secret``) or contains a known credential token
    (``api_key`` → ``apikey``, ``access_token``, ``private_key`` …).
    Deliberately does NOT match ``client_id`` / ``*_id`` / ``public_key`` — a
    public identifier is not a secret.
    """
    if not key or not isinstance(key, str):
        return False
    norm = _normalize_key(key)
    if not norm:
        return False
    if norm.endswith("secret"):
        return True
    return any(tok in norm for tok in SECRET_KEY_TOKENS)


def _looks_populated(value) -> bool:
    """True only if ``value`` is a non-empty string that is not an obvious
    placeholder/sentinel. A real exposed secret has a populated value; ``""``,
    ``null``, ``"changeme"`` or ``"<your-secret>"`` is a non-finding. Non-string
    values (numbers/bools/null, nested objects) are never flagged as a leaked
    secret here. The value's *meaning* is never inspected — only its shape.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 8:
        return False
    if _SECRET_PLACEHOLDER_RE.match(v):
        return False
    return True


def _secret_fingerprint(value) -> str:
    """A short, SALTED, NON-reversible fingerprint of a secret value — just
    enough to prove the SAME secret appeared twice (a stable repeat →
    REPRODUCED) without ever storing or echoing the value. Empty for values
    shorter than 16 chars, where a 12-hex-char prefix would narrow the keyspace
    too much. The salt makes the digest useless outside this process; the value
    itself is never retained anywhere.
    """
    if not isinstance(value, str) or len(value) < 16:
        return ""
    digest = hashlib.sha256((_SECRET_FP_SALT + value).encode("utf-8")).hexdigest()
    return digest[:12]


@dataclass
class SecretExposure:
    """A sensitive KEY observed present in a response body — VALUE REDACTED.

    Holds ONLY non-reversible facts: the key name, its JSON path, the value's
    LENGTH, and a salted fingerprint (``""`` for short values). The secret value
    is deliberately NOT a field, so it cannot leak into a summary, PoC, evidence
    exchange, or saved finding. Proof-of-presence, not proof-by-exfiltration.
    """
    key: str
    path: str
    length: int
    fingerprint: str = ""

    def redacted(self) -> str:
        """A value-free one-line rendering safe to put in any finding field."""
        fp = f" fp={self.fingerprint}" if self.fingerprint else ""
        return f"{self.path} (len={self.length}{fp}) [REDACTED]"


def find_secret_exposures(data, _path: str = "$", _depth: int = 0,
                          _max_depth: int = 6,
                          _max_hits: int = 64) -> List[SecretExposure]:
    """Walk a parsed JSON structure and return a :class:`SecretExposure` for
    every populated secret-named key found. Depth- and count-capped so a hostile
    or huge body cannot exhaust memory. A value is read ONLY to measure its
    length and compute a salted fingerprint — never stored or returned.
    """
    hits: List[SecretExposure] = []

    def _walk(node, path: str, depth: int) -> None:
        if depth > _max_depth or len(hits) >= _max_hits:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                child = f"{path}.{k}"
                if is_secret_key(k) and _looks_populated(v):
                    hits.append(SecretExposure(
                        key=str(k), path=child, length=len(v),
                        fingerprint=_secret_fingerprint(v)))
                else:
                    _walk(v, child, depth + 1)
                if len(hits) >= _max_hits:
                    return
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, f"{path}[{i}]", depth + 1)
                if len(hits) >= _max_hits:
                    return

    _walk(data, _path, _depth)
    return hits


def scan_body_for_secrets(body) -> List[SecretExposure]:
    """Find populated secret-named keys in a response ``body``.

    Prefers a real JSON parse (:func:`find_secret_exposures`); if the body is
    not valid JSON, falls back to a bounded ``"key":"value"`` regex so a secret
    in near-JSON or partially-rendered output is still caught by KEY NAME.
    Returns a list of :class:`SecretExposure`; the value is used only for
    length/fingerprint and is never retained.
    """
    if not body or not isinstance(body, str):
        return []
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    if data is not None:
        return find_secret_exposures(data)
    hits: List[SecretExposure] = []
    for m in _SECRET_JSON_PAIR_RE.finditer(body):
        key, raw = m.group(1), m.group(2)
        if is_secret_key(key) and _looks_populated(raw):
            hits.append(SecretExposure(
                key=key, path=f"$.{key}", length=len(raw),
                fingerprint=_secret_fingerprint(raw)))
            if len(hits) >= 64:
                break
    return hits


def summarize_secret_exposures(hits) -> str:
    """A one-line, VALUE-FREE summary of exposed secret KEYS for a finding
    summary. Lists the distinct key names and the count; never any value."""
    if not hits:
        return "no populated secret-named keys exposed"
    keys: List[str] = []
    for h in hits:
        if h.key not in keys:
            keys.append(h.key)
    shown = ", ".join(keys[:8])
    more = "" if len(keys) <= 8 else f" (+{len(keys) - 8} more)"
    return (f"{len(hits)} populated secret-named value(s) exposed "
            f"(values redacted): {shown}{more}")


# ── Benign, detection-only probes ──────────────
@dataclass
class BenignProbe:
    """A single detection-grade value the engine is allowed to send.

    ``kind`` selects how the response is judged:
      * ``evaluate`` — server-side evaluation (SSTI). Positive when a signature
        appears in the body, the literal payload does NOT (it was rendered),
        and — if a control was sent — the signature is absent from the control
        response (guards against a page that merely contains the number).
      * ``error``    — error-based signal (SQLi). Positive when a DB-error
        signature appears that was absent from the control response.
      * ``reflect``  — the marker is echoed back verbatim / unencoded (XSS
        lead). Reflection ≠ execution, so evidence stays UNVERIFIED.
      * ``redirect`` — the benign canary host appears in the ``Location`` header
        (open redirect). We send GETs with redirects disabled to read it.
    """
    payload: str
    signatures: List[str]
    kind: str = "reflect"
    control: str = ""
    evidence: str = EvidenceLevel.UNVERIFIED
    note: str = ""
    # Decoded form of ``payload`` used by the ``evaluate`` "was it rendered?"
    # guard. For an encoded variant this stays the plain literal (e.g. ``{{7*7}}``)
    # so we still notice when the template did NOT evaluate it. Empty → payload.
    literal: str = ""


# example.com / example.org are IANA-reserved for documentation — a safe
# off-domain canary that points at no real infrastructure.
_REDIRECT_CANARY = "example.com"
# A unique, non-executable reflection marker: metacharacters to test output
# encoding, but no tag name, event handler, or scheme that could ever run.
_XSS_MARKER = "hpr0be'\"<>"
_SQL_ERRORS = [
    "SQL syntax", "ORA-", "PostgreSQL", "SQLITE_ERROR", "unterminated",
    "syntax error", "ODBC", "unclosed quotation", "mysql_fetch",
    "Warning: mysqli", "quoted string not properly terminated",
]

BENIGN_PROBES: Dict[str, List[BenignProbe]] = {
    # Arithmetic differential: {{7*7}} → 49 only if a template engine evaluates
    # it. The control {{7*6}} → 42 lets us reject a page that merely says "49".
    "ssti": [
        BenignProbe("{{7*7}}", ["49"], kind="evaluate", control="{{7*6}}",
                    evidence=EvidenceLevel.INFERRED, note="Jinja2/Twig"),
        BenignProbe("${7*7}", ["49"], kind="evaluate", control="${7*6}",
                    evidence=EvidenceLevel.INFERRED, note="FreeMarker/JSP-EL"),
        BenignProbe("<%= 7*7 %>", ["49"], kind="evaluate", control="<%= 7*6 %>",
                    evidence=EvidenceLevel.INFERRED, note="ERB"),
        BenignProbe("#{7*7}", ["49"], kind="evaluate", control="#{7*6}",
                    evidence=EvidenceLevel.INFERRED, note="Ruby/Thymeleaf"),
    ],
    # A single quote (and double quote) — the smallest non-destructive value
    # that surfaces a DB parse error. Never a boolean/union/time payload.
    "sqli": [
        BenignProbe("'", list(_SQL_ERRORS), kind="error", control="1",
                    evidence=EvidenceLevel.INFERRED, note="single-quote error"),
        BenignProbe('"', list(_SQL_ERRORS), kind="error", control="1",
                    evidence=EvidenceLevel.INFERRED, note="double-quote error"),
    ],
    # Non-executable reflection marker → detects unencoded output only.
    "xss": [
        BenignProbe(_XSS_MARKER, [_XSS_MARKER], kind="reflect",
                    evidence=EvidenceLevel.UNVERIFIED,
                    note="unencoded reflection (lead, not execution)"),
    ],
    # Benign external canary; positive only if it lands in the Location header.
    "open_redirect": [
        BenignProbe(f"https://{_REDIRECT_CANARY}/hydra", [_REDIRECT_CANARY],
                    kind="redirect", evidence=EvidenceLevel.OBSERVED,
                    note="absolute off-domain redirect"),
        BenignProbe(f"//{_REDIRECT_CANARY}/hydra", [_REDIRECT_CANARY],
                    kind="redirect", evidence=EvidenceLevel.OBSERVED,
                    note="scheme-relative off-domain redirect"),
    ],
}


def benign_probes_for(vuln_class: str) -> List[BenignProbe]:
    """Curated detection-only probes for a class (empty if none are safe).

    Classes with no *benign* param probe (ssrf, lfi/path-traversal, idor,
    authz, rce, cors, …) return ``[]`` on purpose — their only safe active
    signal is nuclei's class-tagged templates (Phase 1) or GET path-existence
    checks (Phase 2), never an injected exploitation payload.
    """
    probes = BENIGN_PROBES.get((vuln_class or "").lower(), [])
    # Defense-in-depth: a curated probe must never be exploitation-grade.
    return [p for p in probes if not is_exploitation_payload(p.payload)]


def encoded_variants(probe: "BenignProbe") -> List["BenignProbe"]:
    """WAF-bypass ENCODINGS of a benign probe — same harmless value, wrapped so
    a naive signature filter (one that blocks a literal ``{{`` or ``'``) does not
    drop it before it reaches the app. This is the legitimate half of the
    operator's request: encoding a *benign* detection probe reduces false
    negatives without ever making it harmful.

    Only the transmitted ``payload`` (and its ``control``) is re-encoded; the
    ``signatures`` we look for in the response and the decoded ``literal`` are
    unchanged, because the server decodes before it reflects/evaluates. The
    decoded value is still a benign probe, so :func:`is_exploitation_payload`
    keeps returning False for it.
    """
    out: List["BenignProbe"] = []
    once = quote(probe.payload, safe="")
    twice = quote(once, safe="")
    seen = {probe.payload}
    for enc in (once, twice):
        if enc in seen:
            continue
        seen.add(enc)
        out.append(BenignProbe(
            payload=enc,
            signatures=list(probe.signatures),
            kind=probe.kind,
            control=quote(probe.control, safe="") if probe.control else "",
            evidence=probe.evidence,
            note=f"{probe.note} [url-encoded]" if probe.note else "url-encoded",
            literal=probe.literal or probe.payload,
        ))
    return out


def benign_probe_variants(vuln_class: str) -> List["BenignProbe"]:
    """Curated benign probes for a class PLUS their harmless WAF-bypass encodings.

    Every variant is re-run through :func:`is_exploitation_payload` (payload AND
    control) so nothing exploitation-grade can slip in through an encoding. The
    plain probe is always tried first; encodings are fallbacks for filtered apps.
    """
    out: List["BenignProbe"] = []
    for p in benign_probes_for(vuln_class):
        out.append(p)
        for v in encoded_variants(p):
            if (not is_exploitation_payload(v.payload)
                    and not is_exploitation_payload(v.control)):
                out.append(v)
    return out


def assess_probe(probe: "BenignProbe", *, body: str = "", location: str = "",
                 control_body: str = "") -> bool:
    """Judge a probe response. Returns True on a positive detection.

    Pure and side-effect-free so it is trivially unit-testable offline.
    Handles encoded variants: the response is matched against the decoded
    ``signatures``/``literal`` (the app decodes before reflecting/evaluating).
    """
    body = body or ""
    if probe.kind == "redirect":
        loc = location or ""
        return any(sig in loc for sig in probe.signatures)
    if probe.kind == "reflect":
        # Verbatim (unencoded) echo of the exact marker — accept either the
        # transmitted payload or its decoded signature landing in the body.
        return probe.payload in body or any(s in body for s in probe.signatures)
    if probe.kind in ("evaluate", "error"):
        hit = any(sig in body for sig in probe.signatures)
        if not hit:
            return False
        literal = probe.literal or probe.payload
        if probe.kind == "evaluate" and literal in body:
            return False  # literal survived → not evaluated
        if control_body and any(sig in control_body for sig in probe.signatures):
            return False  # signal present in control too → coincidental
        return True
    return False
