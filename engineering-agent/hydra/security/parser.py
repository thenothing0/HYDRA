"""Security CLI contracts; no runtime initialization on import."""

AVAILABLE_WORKFLOWS = [
    "quick_recon",
    "full_bounty",
    "api_only",
    "web3_audit",
    "blackbox",
    "code_review",
    "hunt",
    "confirm",
    "swarm",
]


def build_parser():
    import argparse

    p = argparse.ArgumentParser(
        prog="hydra security",
        description="HYDRA — Autonomous AI Security Swarm Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m hydra security -t example.com --scope-file scope.json\n"
            "  python -m hydra security --check-tools\n"
            "  python -m hydra security --list-workflows\n"
        ),
    )
    p.add_argument("-t", "--target", help="Target domain or URL")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument(
        "-w",
        "--workflow",
        default="quick_recon",
        choices=AVAILABLE_WORKFLOWS,
        help="Workflow template (default: quick_recon)",
    )
    p.add_argument(
        "--list-workflows", action="store_true", help="Show available workflows"
    )
    p.add_argument("--check-tools", action="store_true", help="Check tool availability")
    p.add_argument(
        "--install-tools", action="store_true", help="Auto-install missing tools"
    )
    p.add_argument(
        "--no-ai", action="store_true", help="Disable AI features (tool-only mode)"
    )
    p.add_argument("--output-dir", default="output", help="Output directory")
    p.add_argument(
        "--scope-url",
        type=str,
        help="Load authorized scope from a program URL (HackerOne/Bugcrowd/Intigriti)",
    )
    p.add_argument(
        "--scope-file",
        type=str,
        help="Load authorized scope from a local JSON file "
        "(keys: program, in_scope, out_of_scope, forbidden_testing)",
    )
    p.add_argument(
        "--scope-token",
        type=str,
        default="",
        help="API token for --scope-url (optional; raises rate limits)",
    )
    p.add_argument(
        "--allow-no-scope",
        action="store_true",
        help="Explicitly run WITHOUT scope enforcement (unsafe; you assert "
        "you are authorized to test the target). Off by default: HYDRA "
        "refuses to scan with no scope loaded (fail-closed).",
    )
    p.add_argument(
        "--timeout", type=int, default=120, help="Per-tool timeout in seconds"
    )
    p.add_argument("--budget", type=float, default=5.0, help="Per-scan AI budget (USD)")
    p.add_argument(
        "--ml-filter",
        action="store_true",
        help="Run the ML models over findings (FP filter + vuln classification)",
    )
    p.add_argument(
        "--ml-threshold",
        type=float,
        default=0.5,
        help="Keep findings with FP probability >= this (default 0.5)",
    )
    p.add_argument(
        "--train-ml",
        action="store_true",
        help="Train the false-positive classifier on recorded feedback and exit",
    )
    p.add_argument(
        "--no-learn",
        action="store_true",
        help="Do NOT record scan findings into the learning database",
    )
    p.add_argument(
        "--no-auto-label",
        action="store_true",
        help="Record findings but skip validation-based auto-labeling",
    )
    p.add_argument(
        "--label",
        nargs=3,
        metavar=("SCAN_ID", "FINDING_ID", "tp|fp"),
        help="Manually label a recorded finding, then exit",
    )
    p.add_argument(
        "--ingest",
        type=str,
        metavar="SOURCES",
        help="Fetch public write-ups to learn from and exit. "
        "Comma-separated sources (e.g. 'github,medium') or 'all'.",
    )
    p.add_argument(
        "--ingest-query",
        type=str,
        default="",
        help="Search/tag query for --ingest (e.g. 'ssrf', 'bug-bounty')",
    )
    p.add_argument(
        "--ingest-limit",
        type=int,
        default=20,
        help="Max write-ups per source for --ingest (default 20)",
    )
    p.add_argument(
        "--ingest-no-train",
        action="store_true",
        help="With --ingest: fetch + index only, skip training",
    )
    p.add_argument(
        "--cve-intel",
        type=str,
        metavar="CVE",
        help="Look up public exploit intelligence for one or more CVEs "
        "(comma-separated) via CISA KEV + NVD, then exit.",
    )
    p.add_argument(
        "--reindex-corpus",
        action="store_true",
        help="Rebuild semantic memory from the on-disk write-up corpus "
        "(upsert; refreshes stale metadata), then exit.",
    )
    # ── Autonomous hunt (workflow "hunt") ──
    p.add_argument(
        "--hunt-class",
        type=str,
        default="auto",
        help="Vuln class for the 'hunt' workflow (ssrf, sqli, xss, "
        "ssti, open_redirect, …) or 'auto' for priority order.",
    )
    p.add_argument(
        "--hunt-mode",
        type=str,
        default="normal",
        choices=["normal", "aggressive", "stealth"],
        help="Hunt intensity (affects nuclei severity range).",
    )
    p.add_argument(
        "--hunt-active",
        action="store_true",
        help="Opt in to benign, scope-gated, rate-limited ACTIVE "
        "detection probing (Phase 2/3). OFF by default — nuclei "
        "only. Never sends exploitation payloads.",
    )
    # ── Benign confirmation (workflow "confirm") ──
    # Human-gated, single-target, scope-gated. NOT part of the autonomous hunt
    # loop: it raises ONE finding's evidence using benign proofs only (controlled
    # differential + repeat, or an OOB callback to a host the operator owns).
    p.add_argument(
        "--confirm-param",
        type=str,
        default="",
        help="Parameter name to confirm for the 'confirm' workflow "
        "(not needed for class 'nextjs', 'sap', 'astro', "
        "'nextjs_ssrf', 'vite', 'web_cache', 'react_router', "
        "'k8s_admission', 'rabbitmq_oauth', 'onelogin_oidc', "
        "'best_fit_charset' or 'dangerous_http_methods' — a "
        "per-route/per-endpoint request-header/path/reachability "
        "or endpoint differential).",
    )
    p.add_argument(
        "--confirm-class",
        type=str,
        default="",
        help="Vuln class to confirm (ssrf, sqli, ssti, open_redirect, "
        "xss, nextjs, sap, astro, nextjs_ssrf, vite, web_cache, "
        "react_router, k8s_admission, rabbitmq_oauth, "
        "onelogin_oidc, best_fit_charset, dangerous_http_methods)."
        " Benign proofs only — no exploitation. best_fit_charset "
        "(CVE-2024-4577 WorstFit) proves only the PHP-CGI "
        "argument-injection CHANNEL via a read-only -v/-V version "
        "banner; it never runs code. dangerous_http_methods "
        "(CVE-2025-24813 Tomcat partial-PUT precondition) reads "
        "the OPTIONS 'Allow' header and flags an advertised write "
        "method (PUT) as the precondition — it never sends "
        "PUT/DELETE/PATCH or uploads a partial-PUT file. The two "
        "secret-overshare classes report an exposed credential "
        "KEY with its value REDACTED.",
    )
    p.add_argument(
        "--oob-callback",
        type=str,
        default="",
        help="For SSRF confirmation: an EXTERNAL callback URL you "
        "control (interactsh / Burp Collaborator). Never a "
        "metadata/internal/loopback host.",
    )
    p.add_argument(
        "--confirm-auth-header",
        type=str,
        default="",
        help="For authorized secret-overshare confirmation "
        "(class 'onelogin_oidc'): the operator's OWN in-scope "
        "API credential as 'Name: value' (e.g. 'Authorization: "
        "Bearer <your-token>'). Forwarded verbatim, GET-only, to "
        "a target you are authorized to test; HYDRA proves a "
        "secret KEY is overshared and REDACTS its value — it "
        "never mints, guesses, reuses, or pivots with a secret.",
    )
    return p
