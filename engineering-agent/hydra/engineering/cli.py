"""CLI for engineering runs, interactive follow-ups and session recovery."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from hydra.console import configure_console

from hydra.engineering.agent import EngineeringAgent, RouterModel
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


def parser():
    root = argparse.ArgumentParser(
        prog="hydra",
        description="HYDRA general-purpose engineering agent",
        epilog="Security workflows: hydra security --help. Explicit engineering entry: hydra engineering --help.",
    )
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("run", "chat", "resume", "tui"):
        command = sub.add_parser(name)
        if name == "run":
            command.add_argument("goal")
        if name == "resume":
            command.add_argument("session_id")
        command.add_argument("--workspace", default=".")
        command.add_argument("--provider", help="Provider id from hydra providers")
        command.add_argument(
            "--model", help="Exact model id/deployment for this provider"
        )
        command.add_argument("--max-steps", type=int, default=30)
        command.add_argument("--max-seconds", type=int, default=600)
        command.add_argument("--max-tool-calls", type=int, help="Tool dispatch limit per run; defaults to max-steps")
        command.add_argument("--max-tokens", type=int, help="Observed provider token ceiling; may exceed by one in-flight request")
        command.add_argument("--max-context-chars", type=int, default=64000)
        command.add_argument("--max-failures", type=int, default=5)
        command.add_argument("--burp-url", help="Official Burp MCP SSE endpoint on loopback (or BURP_MCP_URL)")
        command.add_argument("--read-only", action="store_true")
        command.add_argument(
            "--browser",
            action="store_true",
            help="Enable the paired local browser capability",
        )
        command.add_argument(
            "--allow-browser-actions",
            action="store_true",
            help="Allow scoped page interactions; bridge must allow them too",
        )
        command.add_argument(
            "--allow-run",
            action="store_true",
            help="Authorize local commands without per-command prompts; commands have your OS permissions",
        )
        command.add_argument(
            "--verify-command",
            help='Verification argv as JSON, e.g. ["python","-m","pytest","-q"]',
        )
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--workspace", default=".")
    sessions = sub.add_parser("sessions")
    sessions.add_argument("--workspace", default=".")
    sessions.add_argument("--show", metavar="SESSION_ID")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("session_id")
    rollback.add_argument("--workspace", default=".")
    diff = sub.add_parser("diff")
    diff.add_argument("session_id")
    diff.add_argument("--workspace", default=".")
    handoff = sub.add_parser("handoff", help="Print a validated JSON handoff with evidence references")
    handoff.add_argument("session_id")
    handoff.add_argument("--workspace", default=".")
    providers = sub.add_parser("providers")
    providers.add_argument("--workspace", default=".")
    providers.add_argument("--json", action="store_true")
    burp = sub.add_parser("burp", help="Check the official Burp MCP extension and list its tools")
    burp.add_argument("--workspace", default=".")
    burp.add_argument("--url")
    browser = sub.add_parser("browser", help="Local unpacked-extension bridge")
    commands = browser.add_subparsers(dest="browser_command", required=True)
    for name in ("start", "status", "extension"):
        command = commands.add_parser(name)
        command.add_argument("--workspace", default=".")
        if name == "start":
            command.add_argument("--allow-origin", action="append", required=True)
            command.add_argument("--port", type=int, default=8911)
            command.add_argument("--allow-actions", action="store_true")
    return root


def approve(argv):
    print(
        "\nCommand requests your OS permissions:", json.dumps(argv, ensure_ascii=False)
    )
    if not sys.stdin.isatty():
        return False
    return input("Run this command? [y/N] ").strip().lower() in ("y", "yes")


async def doctor(workspace):
    from hydra.config import get_config
    from hydra.engineering.tools import detect_verification

    cfg = get_config()
    from hydra.engineering.providers import describe_providers, CATALOG

    providers = describe_providers()
    report = {
        "workspace": str(workspace.root),
        "python": sys.version.split()[0],
        "verification_command": detect_verification(workspace.root),
        "providers": {},
        "runtime": "engineering",
        "shell_sandbox": False,
        "provider_catalog": {
            "upstream_commit": CATALOG["commit"],
            "entries": len(providers),
            "transport_profiles": sum(
                p["status"].startswith("implemented") for p in providers
            ),
            "pending_auth": [
                p["id"] for p in providers if p["status"] == "auth_integration_pending"
            ],
            "configured": [p["id"] for p in providers if p["configured"]],
        },
    }
    for name, provider in cfg.ai_providers.items():
        report["providers"][name] = {
            "enabled": provider.enabled,
            "model": provider.model,
        }
    if cfg.ai_providers.get("ollama") and cfg.ai_providers["ollama"].enabled:
        import aiohttp

        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(
                    cfg.ai_providers["ollama"].base_url.rstrip("/") + "/api/tags",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as response:
                    response.raise_for_status()
                    data = await response.json()
            report["providers"]["ollama"]["reachable"] = True
            report["providers"]["ollama"]["installed_models"] = [
                m["name"] for m in data.get("models", [])
            ]
        except Exception as error:
            report["providers"]["ollama"].update(
                reachable=False, error=type(error).__name__
            )
    print(json.dumps(report, indent=2, ensure_ascii=False))


async def start_run(args, workspace, session=None, goal=None, model=None):
    session = session or Session(workspace, goal=goal or args.goal)
    verification = (
        json.loads(args.verify_command)
        if args.verify_command
        else session.state.get("verification_command")
    )
    if verification is not None and (
        not isinstance(verification, list)
        or not verification
        or any(not isinstance(s, str) for s in verification)
    ):
        raise ValueError("--verify-command must be a nonempty JSON array of strings")
    tools = EngineeringTools(
        session,
        approve=(lambda argv: True) if args.allow_run else approve,
        read_only=args.read_only,
        verify_command=verification,
        browser=args.browser,
        allow_browser_actions=args.allow_browser_actions,
        burp_url=getattr(args, "burp_url", None),
        approve_burp=approve,
    )
    session.state["verification_command"] = tools.verify_command
    session.save()
    print(f"Session: {session.state['id']}\nWorkspace: {workspace.root}")
    model = model or RouterModel(args.provider, args.model)
    try:
        await model.initialize()
    except Exception as error:
        session.state["status"] = "blocked"
        session.event("configuration_error", error=str(error))
        raise

    def progress(event):
        print(f"[{event['step']}] {event['tool']}: {event['note']}", flush=True)

    agent = EngineeringAgent(
        session, model, tools, args.max_steps, args.max_seconds, progress,
        max_tool_calls=getattr(args, "max_tool_calls", None), max_tokens=getattr(args, "max_tokens", None),
        max_context_chars=getattr(args, "max_context_chars", 64000), max_failures=getattr(args, "max_failures", 5),
    )
    result = await agent.run()
    print(
        f"\nStatus: {result['status']} | file revisions: {result['revision']} | "
        f"verified revision: {result['verified_revision']}"
    )
    if result.get("summary"):
        print(result["summary"])
    if result.get("run", {}).get("stop_reason"):
        print("Stop reason:", result["run"]["stop_reason"])
    print(f"Evidence: {session.path}")
    return result


async def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, "allow_browser_actions", False) and not args.browser:
        raise ValueError("--allow-browser-actions requires --browser")
    workspace = Workspace(args.workspace)
    if args.command == "handoff":
        session = Session(workspace, session_id=args.session_id)
        print(json.dumps(session.handoff(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "burp":
        from hydra.engineering.burp import BurpClient

        print(json.dumps(await BurpClient(args.url).status(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "browser":
        if args.browser_command == "extension":
            print(Path(__file__).resolve().parents[2] / "extensions/hydra-browser")
            return 0
        if args.browser_command == "start":
            from hydra.browser.bridge import serve

            await serve(
                workspace.root, args.allow_origin, args.port, args.allow_actions
            )
            return 0
        connection = workspace.root / ".hydra/browser/connection.json"
        if not connection.is_file():
            print("Browser bridge is not configured/running for this workspace")
            return 1
        from hydra.browser.bridge import origin

        config = json.loads(connection.read_text(encoding="utf-8"))
        urlsplit_host = origin(config["url"]).split("://", 1)[1].split(":", 1)[0]
        if urlsplit_host != "127.0.0.1":
            raise ValueError("Browser bridge must use loopback")
        import aiohttp

        async with aiohttp.ClientSession() as client:
            async with client.get(
                config["url"] + "/health",
                timeout=aiohttp.ClientTimeout(total=3),
                allow_redirects=False,
            ) as response:
                response.raise_for_status()
                print(json.dumps(await response.json(), indent=2))
        return 0
    if args.command == "doctor":
        await doctor(workspace)
        return 0
    if args.command == "providers":
        from hydra.engineering.providers import describe_providers

        catalog = describe_providers()
        if args.json:
            print(json.dumps(catalog, ensure_ascii=False, indent=2))
        else:
            for item in catalog:
                status = "configured" if item["configured"] else item["status"]
                print(f"{item['id']:25s} {status:28s} {item.get('protocol') or '-'}")
            print(
                "\nimplemented = transport implemented, not live account verification."
            )
            print(
                "auth_integration_pending = listed for parity tracking; cannot be used yet."
            )
        return 0
    if args.command == "sessions":
        if args.show:
            state = Session(workspace, session_id=args.show).state
            print(json.dumps(state, ensure_ascii=False, indent=2))
        else:
            directory = workspace.root / ".hydra/sessions"
            for path in sorted(
                directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
            )[:50]:
                state = Session(workspace, session_id=path.stem).state
                print(f"{state['id']}  {state['status']:18s} {state['goal'][:100]}")
        return 0
    if args.command == "rollback":
        session = Session(workspace, session_id=args.session_id)
        print(
            f"Reverted {session.rollback()} tracked file edits. Command side effects are not rolled back."
        )
        return 0
    if args.command == "diff":
        print(Session(workspace, session_id=args.session_id).diff())
        return 0
    if args.command == "chat":
        if not sys.stdin.isatty():
            raise ValueError("chat needs an interactive terminal; use run for scripts")
        print("HYDRA engineering. /exit to leave; follow-ups share this session.")
        session = None
        model = RouterModel(args.provider, args.model)
        await model.initialize()
        while True:
            goal = input("hydra> ").strip()
            if goal in ("/exit", "/quit"):
                return 0
            if goal:
                if session is None:
                    session = Session(workspace, goal=goal)
                else:
                    session.event(
                        "user_followup", previous_goal=session.state["goal"], goal=goal
                    )
                    session.state.update(
                        goal=goal, status="created", summary="", verified_revision=None
                    )
                    session.save()
                await start_run(args, workspace, session=session, model=model)
    session = (
        Session(workspace, session_id=args.session_id)
        if args.command == "resume"
        else None
    )
    if session and session.state["status"] in ("completed", "rolled_back"):
        raise ValueError("Session is terminal; start a new goal")
    result = await start_run(args, workspace, session=session)
    return 0 if result["status"] == "completed" else 1


def entry(argv=None):
    configure_console()
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        if not arguments or arguments[0] == "tui":
            from hydra.engineering.tui import launch

            launch(parser().parse_args(arguments or ["tui"]))
            return
        raise SystemExit(asyncio.run(main(arguments)))
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Session evidence is saved; use hydra resume <id>.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except (ValueError, OSError, RuntimeError) as error:
        print(f"HYDRA: {error}", file=sys.stderr)
        raise SystemExit(1)
