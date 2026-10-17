"""Security CLI adapter. Engine behavior lives in dedicated components."""

import asyncio
import sys
import logging
from hydra.config import get_config
from hydra.mcp.tool_server import MCPToolServer


from hydra.config import ensure_runtime_directories
from hydra.security.parser import build_parser
from hydra.security.engine import HydraEngine
from hydra.security.console import (
    rprint,
    setup_logging,
    print_tool_status,
    print_workflows,
    print_summary,
)
from hydra.console import configure_console

logger = logging.getLogger("hydra.security")


BANNER = r"""
  _   ___   ______  ____      _
 | | | \ \ / /  _ \|  _ \    / \    v3.0
 | |_| |\ V /| | | | |_) |  / _ \
 |  _  | | | | |_| |  _ <  / ___ \
 |_| |_| |_| |____/|_| \_\/_/   \_\

  Autonomous AI Security Swarm Platform
"""


async def async_main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    ensure_runtime_directories()

    # Banner
    print(BANNER)
    setup_logging(args.verbose)

    # ── List workflows ─────────────
    if args.list_workflows:
        print_workflows()
        return

    # ── Check / install tools ──────
    if args.check_tools or args.install_tools:
        ts = MCPToolServer()
        await ts.initialize()
        print_tool_status(ts)
        if args.install_tools:
            from hydra.bootstrap.installer import auto_install_all

            auto_install_all()
        return

    # ── Ingest public write-ups for learning ──
    if args.ingest:
        from hydra.ingest import IngestPipeline
        import os as _os

        pipeline = IngestPipeline(tokens={"github": _os.getenv("GITHUB_TOKEN", "")})
        available = pipeline.available_sources()
        if args.ingest.strip().lower() == "all":
            sources = available
        else:
            sources = [s.strip() for s in args.ingest.split(",") if s.strip()]
        rprint(
            f"[cyan]📥 Ingesting from:[/] {', '.join(sources)} "
            f"[dim](available: {', '.join(available)})[/dim]"
        )
        result = await pipeline.run(
            sources=sources,
            query=args.ingest_query,
            limit_per_source=args.ingest_limit,
            do_train=not args.ingest_no_train,
        )
        rprint(f"\n[bold]Fetched:[/] {result.get('fetched', 0)} write-ups")
        if result.get("categories"):
            rprint(f"[bold]Categories:[/] {result['categories']}")
        if result.get("corpus"):
            rprint(
                f"[bold]Corpus:[/] +{result['corpus']['added']} new, "
                f"{result['corpus']['total']} total"
            )
        if result.get("kev", {}).get("known_exploited"):
            rprint(
                f"[red]🎯 Known-exploited (CISA KEV):[/] "
                f"{result['kev']['known_exploited']} write-ups flagged"
            )
        if result.get("semantic_stored") is not None:
            rprint(f"[bold]Semantic memory:[/] {result['semantic_stored']} stored")
        tr = result.get("training", {})
        if tr.get("trained"):
            rprint(
                f"[green]✅ Vuln classifier trained[/] — {tr['samples']} samples, "
                f"classes: {tr.get('classes')}, acc {tr['train_accuracy']:.1%}"
            )
        elif tr:
            rprint(f"[yellow]⚠️  Classifier not trained:[/] {tr.get('reason')}")
        return

    # ── Re-index corpus into semantic memory ──
    if args.reindex_corpus:
        from hydra.ingest import IngestPipeline

        res = await IngestPipeline().reindex_semantic()
        if res.get("reindexed"):
            rprint(
                f"[green]♻️  Re-indexed[/] {res['reindexed']} write-ups "
                f"from corpus into semantic memory"
            )
        else:
            rprint(f"[yellow]⚠️  Nothing re-indexed:[/] {res.get('reason')}")
        return

    # ── CVE exploit-intel lookup ───
    if args.cve_intel:
        from hydra.exploits import ExploitIntel, extract_cves

        cves = extract_cves(args.cve_intel) or [
            c.strip().upper() for c in args.cve_intel.split(",") if c.strip()
        ]
        if not cves:
            parser.error("--cve-intel needs at least one CVE id (e.g. CVE-2021-44228)")
        ei = ExploitIntel()
        for cid in cves:
            info = await ei.enrich_cve(cid)
            flag = (
                "[red]⚠️  KNOWN EXPLOITED (CISA KEV)[/]"
                if info.known_exploited
                else "[yellow]public exploit/PoC[/]"
                if info.has_public_exploit()
                else "[dim]no public exploit found[/]"
            )
            rprint(f"\n[bold cyan]{info.cve_id}[/] — {flag}")
            if info.cvss_score is not None:
                rprint(f"  CVSS: {info.cvss_score} {info.cvss_severity}")
            if info.known_exploited:
                rprint(
                    f"  KEV added: {info.kev_date_added}"
                    + ("  [red](ransomware)[/]" if info.kev_ransomware else "")
                )
            if info.description:
                rprint(f"  {info.description[:200]}")
            if info.exploit_refs:
                rprint(f"  [bold]Exploit/PoC references ({len(info.exploit_refs)}):[/]")
                for ref in info.exploit_refs[:8]:
                    rprint(f"    • {ref}")
            rprint(f"  [dim]sources: {', '.join(info.sources) or 'none'}[/]")
        return

    # ── Manual label override ──────
    if args.label:
        scan_id, finding_id, verdict = args.label
        if verdict.lower() not in ("tp", "fp"):
            parser.error("--label verdict must be 'tp' or 'fp'")
        from hydra.learning.pipeline import LearningPipeline

        LearningPipeline().label(scan_id, finding_id, verdict.lower() == "tp")
        rprint(f"[green]✅ Labeled[/] {finding_id} = {verdict.upper()}")
        return

    # ── Train ML models from recorded feedback ──
    if args.train_ml:
        from hydra.learning.engine import LearningEngine

        engine = LearningEngine()
        engine.initialize()
        result = engine.train_fp_classifier()
        if result.get("trained"):
            rprint(
                f"[green]✅ FP classifier trained[/] — "
                f"{result['samples']} samples, "
                f"train accuracy {result['train_accuracy']:.1%}"
            )
            rprint(f"   [dim]{result['model_path']}[/dim]")
        else:
            rprint(
                f"[yellow]⚠️  Not trained:[/] {result.get('reason')} "
                f"(need ≥ {get_config().ml.fp_min_samples} labelled findings; "
                f"have {result.get('have', 0)})"
            )
        return

    # ── Target required below ──────
    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    # ── Run workflow ───────────────
    engine = HydraEngine(
        target=args.target,
        workflow=args.workflow,
        output_dir=args.output_dir,
        timeout=args.timeout,
        ml_filter=args.ml_filter,
        ml_threshold=args.ml_threshold,
        learn=not args.no_learn,
        auto_label=not args.no_auto_label,
        scope_url=args.scope_url or "",
        scope_file=args.scope_file or "",
        scope_token=args.scope_token,
        allow_no_scope=args.allow_no_scope,
        hunt_class=args.hunt_class,
        hunt_mode=args.hunt_mode,
        hunt_active=args.hunt_active,
        confirm_param=args.confirm_param,
        confirm_class=args.confirm_class,
        oob_callback=args.oob_callback,
        confirm_auth_header=args.confirm_auth_header,
        no_ai=args.no_ai,
    )
    await engine.init()
    summary = await engine.run()
    print_summary(summary)
    if summary.get("error"):
        raise SystemExit(1)


def entry(argv=None):
    """Console script entry point."""
    configure_console()
    try:
        asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        rprint("\n[yellow]⚠️  Interrupted — shutting down...[/yellow]")
        raise SystemExit(130)
    except (ValueError, OSError, RuntimeError) as error:
        print(f"HYDRA security: {error}", file=sys.stderr)
        raise SystemExit(1)
