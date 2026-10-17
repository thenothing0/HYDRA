"""Console rendering and logging setup for the security CLI."""

import sys
import logging
from typing import Dict
from hydra.config import LOGS_DIR
from hydra.mcp.tool_server import MCPToolServer
from hydra.security.parser import AVAILABLE_WORKFLOWS

try:
    from rich.console import Console
    from rich.table import Table
    from rich.logging import RichHandler

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

_con = None


def console():
    global _con
    if _con is None:
        _con = Console() if HAS_RICH else None
    return _con


def rprint(msg: str, **kw):
    c = console()
    if c:
        c.print(msg, **kw)
    else:
        print(msg)


# ═══════════════════════════════════════════════
#  Logging setup
# ═══════════════════════════════════════════════


def setup_logging(verbose: bool = False):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    handlers: list = [
        logging.FileHandler(str(LOGS_DIR / "hydra.log"), encoding="utf-8")
    ]

    if HAS_RICH:
        handlers.insert(
            0,
            RichHandler(
                level=level,
                show_path=False,
                show_time=True,
                markup=True,
                rich_tracebacks=True,
            ),
        )
    else:
        handlers.insert(0, logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(message)s"
        if HAS_RICH
        else "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )
    for lib in ["urllib3", "aiohttp", "asyncio", "httpx", "httpcore"]:
        logging.getLogger(lib).setLevel(logging.WARNING)


# ═══════════════════════════════════════════════
#  CLI parser
# ═══════════════════════════════════════════════


def print_tool_status(tool_server: MCPToolServer):
    available = tool_server.get_available_tools()
    if HAS_RICH:
        table = Table(title="🔧 Tool Status", show_lines=False)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="bold")
        for name, ok in sorted(available.items()):
            table.add_row(
                name, "[green]✅ installed[/]" if ok else "[red]❌ missing[/]"
            )
        console().print(table)
    else:
        print("\n🔧 Tool Status:")
        for name, ok in sorted(available.items()):
            print(f"  {'✅' if ok else '❌'} {name}")

    total = len(available)
    ok = sum(1 for v in available.values() if v)
    rprint(f"\n  [bold]{ok}/{total}[/bold] tools available\n")


def print_workflows():
    if HAS_RICH:
        from hydra.workflows import list_workflows

        table = Table(title="📋 Available Workflows")
        table.add_column("Name", style="cyan bold")
        table.add_column("Description")
        table.add_column("Duration", style="dim")
        workflows = {wf["name"]: wf for wf in list_workflows()}
        extras = {
            "hunt": "Scope-gated vulnerability detection loop",
            "confirm": "Benign confirmation of one selected finding",
            "swarm": "Coordinator and pipeline agents in one process",
        }
        for name in AVAILABLE_WORKFLOWS:
            wf = workflows.get(
                name,
                {
                    "name": name,
                    "description": extras.get(name, ""),
                    "duration": "varies",
                },
            )
            table.add_row(wf["name"], wf["description"], wf.get("duration", "?"))
        console().print(table)
    else:
        print("\n📋 Available Workflows:")
        for w in AVAILABLE_WORKFLOWS:
            print(f"  • {w}")
    print()


def print_summary(summary: Dict):
    """Print a final scan summary."""
    if summary.get("error"):
        rprint(f"[red]Scan failed:[/] {summary.get('message', summary['error'])}")
        return
    rprint("\n[bold]═══════════════════════════════════════════════")
    rprint("[bold cyan]📊 HYDRA Scan Summary[/bold cyan]")
    rprint("[bold]═══════════════════════════════════════════════")
    rprint(f"  Target:     [bold]{summary['target']}[/bold]")
    rprint(f"  Workflow:   {summary['workflow']}")
    rprint(f"  Duration:   {summary['elapsed_s']}s")

    recon = summary.get("recon", {})
    if recon:
        rprint(f"\n  [bold]Recon:[/bold]")
        for k, v in recon.items():
            rprint(f"    {k}: {v}")

    fc = summary.get("findings_count", 0)
    colour = "red" if fc > 0 else "green"
    rprint(f"\n  [bold]Findings: [{colour}]{fc}[/{colour}][/bold]")

    if fc > 0:
        for f in summary.get("findings", [])[:20]:
            sev = f.get("severity", "info")
            sev_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            sc = sev_colors.get(sev, "dim")
            rprint(f"    [{sc}][{sev.upper():8s}][/{sc}] {f.get('name', 'N/A')}")
            if f.get("matched_at"):
                rprint(f"             [dim]→ {f['matched_at']}[/dim]")

    rprint(f"\n  Output:     [dim]{summary.get('output_dir', '')}[/dim]")
    rprint("[bold]═══════════════════════════════════════════════\n")
