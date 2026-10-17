"""
╔══════════════════════════════════════════════════════════════╗
║  Swarm Node — Role-aware distributed entrypoint             ║
║  `python -m hydra.swarm` — coordinator | worker | all       ║
╚══════════════════════════════════════════════════════════════╝

This is the OTHER way to run the swarm. Where ``SwarmOrchestrator`` wires the
Coordinator and every pipeline agent into one process, this module is what a
*distributed* deployment runs: each container/pod starts ``python -m hydra.swarm``
and becomes exactly one role, read from ``HYDRA_NODE_ROLE`` (via ``get_config``):

  - ``coordinator`` — the ONLY orchestrator. Connects the (Redis-backed) bus,
    attaches a loaded scope engine (fail-closed), starts the scan, and runs the
    coordinator tick-loop as a long-lived service. Pushes tasks; runs no agent.
  - ``worker``      — connects the same bus, builds the pipeline agents from the
    registry, and runs their pull-loops as a long-lived service. The k8s
    HorizontalPodAutoscaler scales these. Executes tasks the coordinator has
    already scope-gated.
  - ``all`` (default, non-distributed) — one-shot: hands off to
    ``SwarmOrchestrator`` to run a single scan end to end in this process, then
    exits. This is the local/dev/CI path and needs no Redis.

Doctrine:
  - Fail-closed at the node boundary, exactly like ``hydra.main``: with no scope
    loaded and no ``--allow-no-scope``, the coordinator/all node REFUSES to start
    a scan. (The Coordinator's own per-phase gate only fires when a scope engine
    is *loaded*; this node gate is what closes the no-scope-at-all hole.)
  - Nothing here sends traffic. Agents call the MCP tool layer; the never-send
    guardrails live below that and are untouched by the swarm path.
  - Bus selection follows config: distributed → Redis (``redis.url``); otherwise
    in-memory, so a single node still works with zero external services.
"""

import argparse
import asyncio
import logging
import os
import signal
from typing import Optional, Tuple

from hydra.config import get_config
from hydra.memory.bus import MemoryBus
from hydra.swarm.coordinator import CoordinatorAgent
from hydra.swarm.orchestrator import SwarmOrchestrator
from hydra.swarm.registry import build_agents, PIPELINE_AGENT_TYPES

logger = logging.getLogger("hydra.swarm.node")

_TERMINAL_STATES = {"completed", "cancelled", "failed"}


def _env(*names: str, default: str = "") -> str:
    """Return the first non-empty environment variable among ``names``."""
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return default


def build_node_parser() -> argparse.ArgumentParser:
    """CLI for the swarm node. Every flag also reads a container-friendly env."""
    p = argparse.ArgumentParser(
        prog="python -m hydra.swarm",
        description="HYDRA swarm node — role from HYDRA_NODE_ROLE "
                    "(coordinator | worker | all).",
    )
    p.add_argument(
        "-t", "--target", default=_env("TARGET", "HYDRA_TARGET"),
        help="Target domain/URL (coordinator/all). Defaults to $TARGET / $HYDRA_TARGET.",
    )
    p.add_argument(
        "--role", default="",
        help="Override HYDRA_NODE_ROLE (coordinator | worker | all).",
    )
    p.add_argument(
        "--scope-file", default=_env("HYDRA_SCOPE_FILE"),
        help="Authorized-scope JSON file (fail-closed if absent).",
    )
    p.add_argument(
        "--scope-url", default=_env("HYDRA_SCOPE_URL"),
        help="Load scope from a bug-bounty program URL.",
    )
    p.add_argument(
        "--scope-token", default=_env("HYDRA_SCOPE_TOKEN"),
        help="API token for --scope-url.",
    )
    p.add_argument(
        "--allow-no-scope", action="store_true",
        default=_env("HYDRA_ALLOW_NO_SCOPE").lower() == "true",
        help="Run WITHOUT scope (you assert authorization out-of-band).",
    )
    p.add_argument(
        "--timeout", type=float, default=None,
        help="Overall scan timeout in seconds (all role).",
    )
    return p


async def _load_scope(args):
    """Load scope like ``hydra.main`` — an unloaded engine stays fail-closed."""
    import json
    from pathlib import Path
    from hydra.scope import ScopePolicyEngine

    engine = ScopePolicyEngine()
    try:
        if args.scope_file:
            data = json.loads(Path(args.scope_file).read_text(encoding="utf-8"))
            engine.load_from_dict(data)
        elif args.scope_url:
            await engine.load_from_url(args.scope_url, api_token=args.scope_token)
    except Exception as e:
        logger.error(f"Failed to load scope: {e}")
        return ScopePolicyEngine()  # unloaded → validate_target fail-closes
    return engine


def _scope_gate(scope_engine, target: str, allow_no_scope: bool) -> Tuple[bool, str]:
    """Fail-closed node gate mirroring ``hydra.main.run()``.

    With a loaded scope, the target must validate. With no scope loaded, refuse
    unless ``--allow-no-scope`` was asserted. Returns ``(ok, reason)``.
    """
    if scope_engine is not None and scope_engine.is_loaded:
        res = scope_engine.validate_target(target)
        if not res.allowed:
            return False, f"target '{target}' out of scope: {res.reason}"
        return True, "in scope"
    if allow_no_scope:
        return True, "no scope loaded (--allow-no-scope asserted)"
    return False, (
        "no authorized scope loaded (fail-closed) — provide "
        "--scope-file/--scope-url or --allow-no-scope"
    )


def _build_bus() -> MemoryBus:
    """Redis-backed bus when distributed; in-memory otherwise (zero services)."""
    cfg = get_config()
    distributed = cfg.distributed or cfg.queue.mode == "distributed"
    if distributed:
        logger.info(
            f"🔗 Distributed mode — bus over Redis "
            f"({cfg.redis.host}:{cfg.redis.port})"
        )
        return MemoryBus(redis_url=cfg.redis.url)
    logger.info("🧠 Local mode — in-memory bus (no Redis)")
    return MemoryBus()


async def _build_mcp():
    """Best-effort initialized MCP client so workers can execute tools.

    Returns ``None`` on any failure — agents then run their MCP-guarded branches
    as no-ops rather than crashing the node.
    """
    try:
        from hydra.mcp.tool_server import MCPToolServer
        from hydra.mcp.client import MCPClient

        tool_server = MCPToolServer()
        await tool_server.initialize()
        return MCPClient(tool_server=tool_server)
    except Exception as e:
        logger.warning(f"MCP layer unavailable — workers run without tools: {e}")
        return None


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Wire SIGINT/SIGTERM to a graceful stop (best-effort; POSIX only)."""
    loop = asyncio.get_event_loop()
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            # Windows / no signal support on this loop — rely on KeyboardInterrupt.
            pass


async def run_coordinator(args, stop_event: asyncio.Event) -> dict:
    """Long-lived coordinator: gate scope, start the scan, run the tick-loop.

    Runs no agent — workers (separate pods) pull and execute the tasks this
    coordinator pushes. Serves until a stop signal arrives.
    """
    scope = await _load_scope(args)
    if args.target:
        ok, reason = _scope_gate(scope, args.target, args.allow_no_scope)
        if not ok:
            logger.error(f"🚫 REFUSING TO SCAN — {reason}")
            return {"error": "scope_refused", "message": reason}

    bus = _build_bus()
    await bus.connect()
    coordinator = CoordinatorAgent(bus, scope_engine=scope)
    if scope is not None and scope.is_loaded:
        coordinator.set_scope_engine(scope)

    loop_task = asyncio.create_task(coordinator.run())
    scan_id: Optional[str] = None
    try:
        if args.target:
            scan_id = await coordinator.start_scan(args.target, {})
            logger.info(f"🎯 Coordinator started scan {scan_id} → {args.target}")
        else:
            logger.info("🎛️  Coordinator idle — no target given; serving bus only.")
        await stop_event.wait()
    finally:
        await coordinator.stop()
        loop_task.cancel()
        await asyncio.gather(loop_task, return_exceptions=True)
        await bus.disconnect()
    return {"role": "coordinator", "scan_id": scan_id}


async def run_worker(args, stop_event: asyncio.Event) -> dict:
    """Long-lived worker: build the pipeline agents and run their pull-loops.

    Workers hold no scope engine — every task they pull was already scope-gated
    by the coordinator before it hit the bus.
    """
    bus = _build_bus()
    await bus.connect()
    mcp = await _build_mcp()
    agents = build_agents(PIPELINE_AGENT_TYPES, bus, mcp_client=mcp)
    logger.info(
        f"👷 Worker {get_config().node_id} up: {len(agents)} agents "
        f"({', '.join(a.AGENT_TYPE for a in agents)})"
    )

    loop_tasks = [asyncio.create_task(a.run()) for a in agents]
    try:
        await stop_event.wait()
    finally:
        for a in agents:
            await a.stop()
        for t in loop_tasks:
            t.cancel()
        await asyncio.gather(*loop_tasks, return_exceptions=True)
        await bus.disconnect()
    return {"role": "worker", "agents": [a.AGENT_TYPE for a in agents]}


async def run_all(args) -> dict:
    """One-shot single-process scan via ``SwarmOrchestrator`` (local/dev/CI)."""
    if not args.target:
        logger.error("🚫 No target given (set --target or $TARGET).")
        return {"error": "no_target"}

    scope = await _load_scope(args)
    ok, reason = _scope_gate(scope, args.target, args.allow_no_scope)
    if not ok:
        logger.error(f"🚫 REFUSING TO SCAN — {reason}")
        return {"error": "scope_refused", "message": reason}

    mcp = await _build_mcp()
    orch = SwarmOrchestrator(
        mcp_client=mcp,
        scope_engine=scope if scope.is_loaded else None,
        timeout=args.timeout,
    )
    result = await orch.run_scan(args.target, {})
    logger.info(
        f"🏁 Swarm scan finished: status={result.get('status')}, "
        f"findings={len(result.get('findings', []))}"
    )
    return result


def _resolve_role(args) -> str:
    """Effective role: --role beats HYDRA_NODE_ROLE; unknown values → 'all'."""
    role = (args.role or get_config().node_role or "all").strip().lower()
    return role if role in ("coordinator", "worker", "all") else "all"


async def run_node(args) -> dict:
    """Dispatch to the role handler. 'all' is one-shot; the others are services."""
    role = _resolve_role(args)
    logger.info(f"🐝 HYDRA swarm node starting — role={role}")

    if role == "all":
        return await run_all(args)

    stop_event = asyncio.Event()
    _install_signal_handlers(stop_event)
    if role == "coordinator":
        return await run_coordinator(args, stop_event)
    return await run_worker(args, stop_event)


def main() -> None:
    """Entrypoint for ``python -m hydra.swarm``."""
    args = build_node_parser().parse_args()
    try:
        from hydra.main import setup_logging
        setup_logging(verbose=False)
    except Exception:
        logging.basicConfig(level=logging.INFO)

    try:
        asyncio.run(run_node(args))
    except KeyboardInterrupt:
        logger.warning("Interrupted — shutting down swarm node.")


if __name__ == "__main__":
    main()
