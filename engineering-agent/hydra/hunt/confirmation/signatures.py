"""Existing benign probe signatures and limits, shared by confirmation handlers."""

import re

# Classes with a safe, benign reproduction path in HYDRA. Everything else is
# honestly reported as "manual verification required" — HYDRA will not automate
# an exploitation-grade proof.
_DIFFERENTIAL_CLASSES = {"ssti", "sqli", "open_redirect", "xss"}

# CVE-2025-29927 — Next.js middleware auth bypass. Setting this request header
# makes a vulnerable Next.js treat the request as an internal subrequest and
# SKIP middleware (which commonly enforces auth / redirects). Detection is a
# pure ACCESS-CONTROL STATUS DIFFERENTIAL: a route that is gated (401/403/
# redirect) WITHOUT the header returns 200 WITH it. We observe the status flip
# only — HYDRA never reads, extracts, or acts on the protected data behind the
# gate. The header name/values are all benign tokens (they pass the
# is_exploitation_payload denylist and the header-splitting checks in safety.py).
_NEXT_MW_HEADER = "x-middleware-subrequest"
_NEXT_MW_VALUES = [
    "middleware",
    "src/middleware",
    "pages/_middleware",
    "src/pages/_middleware",
    # 15.x resolves the header recursively up to MAX_RECURSION_DEPTH (5); the
    # repeated form satisfies that code path.
    "middleware:middleware:middleware:middleware:middleware",
]

# CVE-2025-31324 — SAP NetWeaver Visual Composer "Metadata Uploader". On
# vulnerable NetWeaver AS Java the servlet at
# /developmentserver/metadatauploader is reachable WITHOUT authentication, and a
# multipart POST there uploads a JSP webshell → RCE (CISA KEV, mass-exploited).
# HYDRA proves ONLY the pre-auth REACHABILITY of the endpoint via a benign
# unauthenticated GET status differential. It NEVER sends the POST upload (that
# upload IS the exploit) and never touches the CVE-2025-42999 Visual Composer
# deserialization sink, which stays detection-only.
_SAP_UPLOADER_PATH = "/developmentserver/metadatauploader"
_SAP_APP_ROOT = "/developmentserver/"
# Passive fingerprint markers (Server banner / body) — ANNOTATION only, never a
# gate on the verdict; the reachability differential is what confirms the finding.
_SAP_FINGERPRINTS = (
    "sap netweaver",
    "sap ag",
    "visual composer",
    "metadatauploader",
    "com.sap",
    "/irj/",
    "sap j2ee",
    "sap application server",
)

# CVE-2025-64525 — Astro on-demand middleware forwarded-origin trust. Astro
# derives the request origin from X-Forwarded-* headers; middleware that gates a
# route on host / proto / port can be bypassed by spoofing them. Detection is a
# pure ACCESS-CONTROL STATUS DIFFERENTIAL: a route gated (401/403/redirect)
# WITHOUT the headers returns 200 when the forwarded origin is spoofed. To stay
# benign AND avoid poisoning a shared cache for OTHER users, HYDRA only ever
# spoofs to an EMPTY value or the target's OWN hostname — NEVER a foreign host a
# shared cache could replay. Status only; the gated content is never read.
_ASTRO_FWD_HEADER = "x-forwarded-host"

# CVE-2025-57822 — Next.js NextResponse.next({request:{headers}}) reflecting
# attacker-supplied request headers into the forwarded/outbound path (the
# header-reflection PRECONDITION for SSRF). HYDRA sends one benign, unique marker
# request header and checks ONLY whether that exact marker is echoed back (body
# or a response header) that a header-less control did NOT contain. Reflection is
# a LEAD, not SSRF execution — the actual SSRF proof stays the operator-owned OOB
# callback path (--confirm-class ssrf --oob-callback), so this never claims SSRF
# on its own and never reads an internal / metadata host.
_HDR_REFLECT_NAME = "x-hydra-probe"

# CVE-2025-43865 — React Router v7 / Remix prerender-data spoofing. On vulnerable
# versions the server trusts a client-supplied ``X-React-Router-Prerender-Data``
# request header and serialises its per-route ``data`` straight into the server-
# rendered HTML. HYDRA proves ONLY the spoofing CHANNEL: it injects a UNIQUE,
# pure-alnum, operator-owned nonce marker as the route data; if that exact marker
# appears in the HTML of the header-carrying request but NOT in a header-less
# control, the server reflected client-controlled prerender data = the spoofing
# precondition is present. The marker is pure ``[A-Za-z0-9]`` (enforced by
# _RR_VALUE_RE) so it carries NO HTML metacharacter — it can never demonstrate
# executable XSS or cross-user cache poisoning; those impacts stay UNproven. The
# JSON wrapper ``{"root":{"data":"<marker>"}}`` contains only braces, quotes,
# colons and the word ``data`` — none is an EXPLOITATION_MARKER (``data`` ≠ the
# ``data:text/html`` scheme marker), so the whole value passes
# is_exploitation_payload and the denylist stays fully intact.
_RR_PRERENDER_HEADER = "x-react-router-prerender-data"
_RR_ROUTE_IDS = ("root",)
_RR_VALUE_RE = re.compile(r"^[A-Za-z0-9]{8,}$")

# CVE-2025-30208 — Vite dev server ``server.fs.deny`` bypass. Vite blocks files
# matching server.fs.deny (default: .env, .env.*, *.{crt,pem}, **/.git/**) with
# HTTP 403 BEFORE it checks whether the file exists. A trailing-separator query
# trick (``?raw??`` / ``?import&raw??``) makes a vulnerable Vite skip that deny
# check so the request reaches the file loader. HYDRA proves ONLY the PRESENCE
# of the bypass via a STATUS differential on a guaranteed-NONEXISTENT, nonce'd
# canary that matches a default deny pattern — it reads ZERO file content and
# uses NO ../ traversal, file://, or /@fs/ path. Presence is static, so this
# caps at OBSERVED and never claims a secret was read. The canary names + bypass
# suffixes are all benign strings (no EXPLOITATION_MARKERS: '.env'/'.pem'/'.txt'
# /'raw'/'import' are not markers, and there is no traversal token), so they
# pass is_exploitation_payload and the denylist is left fully intact.
_VITE_DENY_CANARIES = (".env.{nonce}", "{nonce}.pem")
_VITE_BYPASS_SUFFIXES = ("?raw??", "?import&raw??")

# CVE-2025-57752 — Next.js Image Optimization (/_next/image) cache-key confusion.
# The optimizer negotiates the output format (AVIF / WebP / original) from the
# request ``Accept`` header, but the vulnerable versions omit that header from
# the cache key — so a response optimized for one Accept is served to a client
# that sent a DIFFERENT Accept (a cache-poisoning precondition). HYDRA proves
# ONLY the mis-keying PRESENCE and does it WITHOUT ever poisoning a real user:
# every request carries a UNIQUE nonce inside the inner ``url`` value (which the
# optimizer keys on), so the cache entry is isolated to the operator and no real
# user ever shares it. Per fresh-nonce round it sends request A (Accept #1) to
# populate, then request B (Accept #2, a DIFFERENT negotiated format) against the
# SAME key on B's first-ever send — if B is served a cache HIT of A, the Accept
# header is confused out of the key. It reads a benign image only (zero other-
# user content), is GET-only, and honestly reports PRESENCE (a precondition),
# never a demonstrated cross-user poisoning impact. The header name/values are
# benign standard content-negotiation tokens (no EXPLOITATION_MARKERS), so they
# pass is_exploitation_payload and the denylist is left fully intact.
_NEXT_IMAGE_PATH = "/_next/image"
_IMG_VARY_HEADER = "accept"
# Two benign content-negotiation Accept values that make the optimizer negotiate
# DIFFERENT output formats (A → AVIF, B → original PNG). We deliberately avoid the
# `*/*` wildcard range: the substring `/*` is a SQL-inline-comment EXPLOITATION_MARKER,
# so a literal `*/*` would be refused by is_safe_probe_header (fail-closed) and the
# probe would never send. These wildcard-free media types carry no marker, pass
# is_exploitation_payload, and leave the denylist fully intact.
_IMG_ACCEPT_A = "image/avif,image/webp"  # modern client → optimizer picks AVIF
_IMG_ACCEPT_B = "image/png"  # legacy client → original format, no avif/webp
# Benign local raster-image candidates (the optimizer rejects SVG/ICO by default)
# tried when the operator points HYDRA at an app origin rather than a known-good
# /_next/image URL. First one that yields a cacheable 200 is used.
_IMG_LOCAL_CANDIDATES = (
    "/icon.png",
    "/apple-icon.png",
    "/apple-touch-icon.png",
    "/logo.png",
    "/images/logo.png",
    "/favicon.png",
)
# Response headers that reveal whether a response was served from a cache.
_CACHE_STATUS_HEADERS = (
    "x-vercel-cache",
    "x-nextjs-cache",
    "cf-cache-status",
    "x-cache",
    "x-vercel-cache-state",
    "fastly-cache",
    "cdn-cache",
    "x-cache-status",
)

# CVE-2025-1974 — IngressNightmare. The ingress-nginx *admission controller*
# runs a validating-webhook HTTPS server (default :8443) that is meant to be
# reached ONLY by the in-cluster kube-apiserver. When it is network-reachable
# from an attacker vantage point, an unauthenticated AdmissionReview POST
# carrying a crafted Ingress object (annotations that inject nginx config +
# load a shared library) yields RCE on the controller. HYDRA proves ONLY the
# EXPOSURE PRECONDITION: that the admission server answers an UNAUTHENTICATED,
# client-cert-less GET from outside the cluster (SafeProber presents no client
# certificate, so a 200 here demonstrates it is NOT restricted to mTLS apiserver
# traffic). It confirms the service identity with GET-only fingerprints — a
# ``/healthz`` liveness 200 plus the admission webhook path rejecting a bare GET
# (405 / content-type error / "AdmissionReview") — and NEVER sends the
# AdmissionReview POST (that POST IS the exploit). Presence is static, so this
# caps at OBSERVED and never claims RCE. All probe URLs are benign fixed paths
# (``/healthz``, ``/networking/v1/ingresses``) with no EXPLOITATION_MARKERS, so
# they pass is_exploitation_payload and the denylist is left fully intact.
_K8S_HEALTHZ_PATH = "/healthz"
_K8S_WEBHOOK_PATH = "/networking/v1/ingresses"
# Admission-controller identity markers (Server banner / body / webhook response)
# — a GATE on the verdict here (unlike SAP's annotation-only fingerprint): a bare
# 200 on /healthz is not admission-specific, so HYDRA will not call any reachable
# service an exposed ingress-nginx admission controller without one of these.
_K8S_ADMISSION_FINGERPRINTS = (
    "admissionreview",
    "admission webhook",
    "expected application/json",
    "invalid content type",
    "contenttype=",
    "ingress-nginx",
    "nginx ingress",
    "/networking/v1/ingresses",
    "kube-webhook",
)

# ---------------------------------------------------------------------------
# Static-JS cluster (P19-P22) — detect-only client-side confirmers.
#
# ALLOWED (what every method below does): GET the target's OWN HTML, then GET
# the ``<script src>`` bundles it references (SafeProber: GET-only, redirects
# off, scope-gated fail-closed so a foreign CDN that is NOT in scope is simply
# refused, rate-limited, request-capped). Read the SERVED source text and match
# a version fingerprint + a known-vulnerable static code signature, OR read the
# CSP the target already sends. All reads are of publicly served assets.
#
# REFUSED (never done here): building or sending the prototype-pollution / XSS /
# DOM-clobbering payload, posting a cross-document ``message``, triggering any
# sink, or executing/importing the fetched script. The XSS/PP/clobbering PAYOFF
# stays DETECT-ONLY — HYDRA reports the PRECONDITION (a vulnerable library build
# is served) at OBSERVED (static presence), never REPRODUCED, never "exploited".
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_MAX_JS_BUNDLES = 12  # request-budget cap on bundles fetched per target

# P19 — DOMPurify prototype-pollution, CVE-2026-41238. Vulnerable builds in
# [3.0.1, 3.4.0) take a PLAIN ``{}`` fallback for CUSTOM_ELEMENT_HANDLING, so a
# polluted Object.prototype leaks tagNameCheck/attributeNameCheck through it;
# 3.4.0+ fall back to a null-prototype object. Version is the discriminator vs
# the patch; the CUSTOM_ELEMENT_HANDLING token confirms we really found the
# vulnerable code path (not an unrelated ``version`` string in some other lib).
_DOMPURIFY_RANGE = ((3, 0, 1), (3, 4, 0))
_DOMPURIFY_BANNER_RE = re.compile(r"DOMPurify\s+(\d+\.\d+\.\d+)", re.I)
_DOMPURIFY_VER_RE = re.compile(r"\.version\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']")
_DOMPURIFY_TOKEN_RE = re.compile(r"\bDOMPurify\b", re.I)
_DOMPURIFY_SIG_RE = re.compile(r"CUSTOM_ELEMENT_HANDLING", re.I)
# The vulnerable ``|| {}`` fallback (readable + minified) — a corroborating
# structural signal when present; absence does not clear a version-in-range hit.
_DOMPURIFY_FALLBACK_RE = re.compile(r"CUSTOM_ELEMENT_HANDLING\s*\|\|\s*\{\s*\}")

# P20 — missing-origin cross-document message handler → HTML sink (the DOM
# postMessage-XSS precondition; cf. WooCommerce CVE-2025-5062). A ``message``
# listener whose body reaches an innerHTML-family sink with NO origin check in
# between is the vulnerable shape. Evaluated PER source file (not across files).
_MSG_LISTENER_RE = re.compile(r"addEventListener\s*\(\s*[\"']message[\"']", re.I)
_ORIGIN_CHECK_RE = re.compile(
    r"\.origin\b|\borigin\s*(===|!==|==|!=)|checkorigin|allowedorigins"
    r"|trustedorigins|originallowlist|event\.source",
    re.I,
)
_HTML_SINK_RE = re.compile(
    r"\.innerHTML\b|insertAdjacentHTML|\.outerHTML\b|document\.write", re.I
)
_MSG_WINDOW = 900  # chars of source after the listener to inspect
_WOO_GENERATOR_RE = re.compile(r"WooCommerce\s+(\d+\.\d+(?:\.\d+)?)", re.I)

# P21 — Bootstrap 3 tooltip/popover DOM-clobbering in the HTML sanitizer,
# CVE-2025-1647. The ``sanitizeHtml``/``createHTMLDocument`` sanitizer shipped
# from 3.4.x; Bootstrap 3 is EOL so all [3.4.1, 4.0.0) remain affected.
_BOOTSTRAP_RANGE = ((3, 4, 1), (4, 0, 0))
_BOOTSTRAP_BANNER_RE = re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I)
_BOOTSTRAP_VER_RE = re.compile(r"VERSION\s*[:=]\s*[\"'](\d+\.\d+\.\d+)[\"']")
_BOOTSTRAP_SIG_TOKENS = ("createHTMLDocument", "sanitizeHtml")

# P22 — nonce-based CSP bypass PRECONDITIONS (no CVE; passive posture). Reads
# ONLY the CSP the target itself sends (response header + ``<meta http-equiv>``)
# and compares the nonce across two independent GETs. Reports Low/Info; sends
# nothing but two plain GETs of the target's own page.
_CSP_META_RE = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*[\"']content-security-policy[\"'][^>]*>", re.I
)
_CSP_META_CONTENT_RE = re.compile(r"content\s*=\s*([\"'])(.*?)\1", re.I)
_CSP_NONCE_RE = re.compile(r"'nonce-([A-Za-z0-9+/=_\-]+)'")

# CVE-2026-5721 — RabbitMQ management plugin unauth OAuth config leak. On a
# vulnerable management plugin an UNAUTHENTICATED GET of the management API's
# auth/settings endpoint returns the broker's OAuth 2 config, which can include
# the confidential ``oauth_client_secret`` / ``client_secret``. HYDRA proves
# ONLY that a sensitive secret KEY is reachable by an unauthenticated reader and
# REDACTS its value (presence + length + salted, non-reversible fingerprint). It
# never reads, echoes, stores, or authenticates with the leaked secret.
_RABBITMQ_AUTH_PATHS = (
    "/api/auth",
    "/api/definitions",
)

# CVE-2025-59363 — OneLogin OIDC app-listing secret overshare. An AUTHENTICATED
# GET of the admin API app-listing endpoint, made with the OPERATOR'S OWN
# in-scope API credential, returns each OIDC app's confidential ``client_secret``
# (and sometimes ``api_key``) — data the endpoint should not return. HYDRA uses
# only the operator's own authorized token (supplied via --confirm-auth-header),
# proves a secret KEY is overshared, and REDACTS the value. It never mints,
# guesses, reuses, or pivots with a leaked secret.
_ONELOGIN_APP_PATHS = (
    "/api/2/apps",
    "/api/1/apps",
)

# CVE-2024-4577 — PHP-CGI "WorstFit" Best-Fit charset ARGUMENT injection. On
# Windows, php-cgi.exe is reached through a code path that applies the active
# locale's *Best-Fit* character mapping to the raw query string AFTER the web
# server has quoted it. A benign Unicode look-alike — U+00AD SOFT HYPHEN, sent
# on the wire as the single percent-octet ``%AD`` — is silently folded to an
# ASCII ``-``, so a query of ``?%ADv`` reaches php-cgi as the command-line flag
# ``-v``. HYDRA proves ONLY that the look-alike is mapped onto a CLI flag, using
# the single READ-ONLY ``-v``/``-V`` (print version) flag: if ``?%ADv`` makes a
# PHP version banner appear that a plain control request did NOT, the WorstFit
# argument-injection CHANNEL is present. The version banner is public
# fingerprint data; the FINDING is the injection channel, not RCE — so it caps
# at OBSERVED and is never 'critical'.
#
# HARD benign boundary (enforced in _confirm_best_fit_charset): HYDRA only ever
# injects a flag from ``_WORSTFIT_FLAGS`` = {-v, -V}. It NEVER injects ``-d`` (set
# a php.ini directive → the ``allow_url_include`` / ``auto_prepend_file=
# php://input`` RCE chain), ``-s`` (source / file disclosure), ``-r`` / ``-f``
# (run code / a file) or ``-i`` (phpinfo → env & secret leak), and it NEVER sends
# the ``php://input`` POST body that completes CVE-2024-4577. The look-alike probe
# is a bare, isolated version flag that carries no exploitation marker, so it
# passes is_exploitation_payload / _fold_unicode and is never auto-refused.
_WORSTFIT_SOFT_HYPHEN = "%AD"  # U+00AD; Best-Fit-folds to ASCII '-'
_WORSTFIT_FLAGS = ("v", "V")  # print-version ONLY — read-only allow-list
_WORSTFIT_PHP_PATHS = (  # common Windows php-cgi handler endpoints
    "/index.php",
    "/php-cgi/php-cgi.exe",
    "/cgi-bin/php-cgi.exe",
    "/cgi-bin/php.exe",
)
# Signatures that only a ``php -v`` / ``-V`` banner emits — never normal app HTML.
_WORSTFIT_VERSION_RE = re.compile(
    r"PHP\s+[5-9]\.\d+(?:\.\d+)?|Zend\s+Engine|Zend\s+Technologies|"
    r"Copyright\s+\(c\)\s+The\s+PHP\s+Group|\(cgi-fcgi\)",
    re.IGNORECASE,
)

_NO_BENIGN_PROOF = (
    "No benign, non-exploitative reproduction exists for this class in HYDRA. "
    "Confirming it safely (without executing code, extracting data, disclosing "
    "files, or reaching internal/metadata hosts) requires manual, authorized "
    "verification by the operator. HYDRA will not automate an exploitation PoC."
)

# ── P8: CVE-2025-24813 Tomcat partial-PUT precondition (dangerous HTTP methods) ──
# Mutating/write verbs HYDRA only ever OBSERVES as *advertised* in an OPTIONS
# ``Allow`` header; they are NEVER sent. Reading that a server advertises PUT is a
# precondition/indicator — not an exploit, and never proof of RCE.
_DANGEROUS_WRITE_METHODS = ("PUT", "DELETE", "PATCH")
# The specific write verb whose advertisement is the CVE-2025-24813 partial-PUT
# RCE precondition: a default servlet with writes enabled (``readonly=false``).
_PARTIAL_PUT_METHOD = "PUT"
# Public Server-banner fingerprint narrowing a PUT-enabled host to the exact
# Tomcat/Coyote stack of CVE-2025-24813 (annotation only — never required).
_TOMCAT_SERVER_RE = re.compile(r"Tomcat|Coyote|Apache-Coyote", re.IGNORECASE)
