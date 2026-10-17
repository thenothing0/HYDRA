"""
╔══════════════════════════════════════════════════════════════╗
║  MCP HTTP Server — JSON-RPC API for tool execution          ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from aiohttp import web

from hydra.mcp.tool_server import MCPToolServer, TOOL_REGISTRY

logger = logging.getLogger("hydra.mcp.http")


class MCPHTTPServer:
    """HTTP server exposing MCP tool execution via JSON-RPC."""

    def __init__(self, tool_server: MCPToolServer, host: str = "127.0.0.1",
                 port: int = 8900, fail_closed: bool = True):
        self.tool_server = tool_server
        self.host = host
        self.port = port
        # Refuse execution without scope unless explicitly overridden by the operator.
        self.fail_closed = fail_closed
        self._runner = None
        self.app = web.Application()
        self._setup_routes()

    def _scope_loaded(self) -> bool:
        eng = getattr(self.tool_server, "_scope_engine", None)
        return bool(eng is not None and eng.is_loaded)
    
    def _setup_routes(self):
        self.app.router.add_post("/execute", self.handle_execute)
        self.app.router.add_get("/tools", self.handle_list_tools)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/stats", self.handle_stats)
    
    async def handle_execute(self, request: web.Request) -> web.Response:
        """Execute a tool via MCP."""
        try:
            body = await request.json()
            if not isinstance(body, dict):
                return web.json_response({"error": "JSON body must be an object"}, status=400)
            tool_name = body.get("tool")
            params = body.get("params", {})
            timeout = body.get("timeout")
            if (not isinstance(params, dict)
                    or (tool_name is not None and not isinstance(tool_name, str))
                    or (timeout is not None and (type(timeout) is not int or timeout <= 0))):
                return web.json_response({"error": "Invalid tool, params or timeout"}, status=400)
            if (any(key in params and not isinstance(params[key], str)
                    for key in ("target", "_stdin", "tool"))
                    or ("targets" in params and (not isinstance(params["targets"], list)
                        or any(not isinstance(t, str) for t in params["targets"])))):
                return web.json_response({"error": "Invalid target parameters"}, status=400)
            
            if not tool_name:
                return web.json_response(
                    {"error": "Missing 'tool' field"}, status=400
                )

            # Fail-closed gate: with no authorized scope loaded, refuse to run
            # any tool unless the operator explicitly allowed no-scope at launch.
            if self.fail_closed and not self._scope_loaded():
                return web.json_response({
                    "success": False, "blocked_by_scope": True, "output": "",
                    "error": ("No authorized scope loaded (fail-closed). Set "
                              "HYDRA_SCOPE_FILE=<json> or HYDRA_SCOPE_URL=<program> "
                              "(optionally HYDRA_SCOPE_TOKEN), or HYDRA_ALLOW_NO_SCOPE=1 "
                              "to assert you are authorized."),
                }, status=403)

            result = await self.tool_server.execute_tool(tool_name, params, timeout)
            return web.json_response(result)
            
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        except Exception as e:
            logger.error(f"Execute error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def handle_list_tools(self, request: web.Request) -> web.Response:
        """List all registered tools and their availability."""
        tools = {}
        available = self.tool_server.get_available_tools()
        for name, tool_def in TOOL_REGISTRY.items():
            tools[name] = {
                "description": tool_def["description"],
                "binary": tool_def["binary"],
                "available": available.get(name, False),
            }
        return web.json_response({"tools": tools})
    
    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy", "service": "mcp-tool-server"})
    
    async def handle_stats(self, request: web.Request) -> web.Response:
        return web.json_response(self.tool_server.get_stats())
    
    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        self._runner = runner
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"🌐 MCP HTTP Server running at http://{self.host}:{self.port}")
    
    async def start_standalone(self):
        """Initialize tools and serve until interrupted (blocking on the loop).

        Uses AppRunner via ``start()`` rather than ``web.run_app`` — the latter
        creates and drives its own event loop and cannot be awaited from inside
        a running one, which is exactly how this coroutine is launched.
        """
        await self.tool_server.initialize()
        await self.start()
        logger.info(f"🌐 MCP HTTP Server ready on http://{self.host}:{self.port}")
        if self.fail_closed and not self._scope_loaded():
            logger.warning(
                "⚠️  FAIL-CLOSED: no authorized scope loaded — all tool "
                "executions are refused. Set HYDRA_SCOPE_FILE / HYDRA_SCOPE_URL, "
                "or HYDRA_ALLOW_NO_SCOPE=1 to run without a loaded scope."
            )
        try:
            await asyncio.Event().wait()  # serve forever
        finally:
            if self._runner is not None:
                await self._runner.cleanup()


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


async def _load_scope_from_env() -> tuple:
    """Load an authorized scope from the environment.

    Returns ``(engine_or_None, allow_no_scope)``. Mirrors the root MCP server:
    HYDRA_SCOPE_FILE / HYDRA_SCOPE_URL / HYDRA_SCOPE_TOKEN load the scope;
    HYDRA_ALLOW_NO_SCOPE (or globally disabling enforcement) asserts authorization
    when no scope is provided. On any load error we stay fail-closed.
    """
    try:
        from hydra.scope import ScopePolicyEngine
        from hydra.config import get_config
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"scope module unavailable ({e}); fail-closed unless "
                       f"HYDRA_ALLOW_NO_SCOPE=1")
        return None, _env_true("HYDRA_ALLOW_NO_SCOPE")

    allow_no_scope = _env_true("HYDRA_ALLOW_NO_SCOPE")
    try:
        if not get_config().scope.enforce_scope:
            allow_no_scope = True
    except Exception:
        pass

    scope_file = os.getenv("HYDRA_SCOPE_FILE", "").strip()
    scope_url = os.getenv("HYDRA_SCOPE_URL", "").strip()
    scope_token = os.getenv("HYDRA_SCOPE_TOKEN", "").strip()
    if not (scope_file or scope_url):
        return None, allow_no_scope

    eng = ScopePolicyEngine()
    try:
        if scope_file:
            data = json.loads(Path(scope_file).read_text(encoding="utf-8"))
            eng.load_from_dict(data)
        else:
            await eng.load_from_url(scope_url, api_token=scope_token)
    except Exception as e:
        logger.error(f"Failed to load scope: {e} — staying fail-closed")
        return None, allow_no_scope
    return eng, allow_no_scope


async def _amain() -> None:
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8900"))

    tool_server = MCPToolServer()
    engine, allow_no_scope = await _load_scope_from_env()
    if engine is not None:
        tool_server.set_scope_engine(engine)

    scope_loaded = bool(engine is not None and engine.is_loaded)
    fail_closed = not (scope_loaded or allow_no_scope)

    server = MCPHTTPServer(tool_server, host=host, port=port, fail_closed=fail_closed)
    await server.start_standalone()


def main() -> None:
    logging.basicConfig(
        level=os.getenv("HYDRA_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        logger.info("MCP HTTP Server stopped.")


if __name__ == "__main__":
    main()
