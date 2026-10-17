"""Built-in client for the official PortSwigger Burp MCP extension."""

import asyncio
import inspect
import json
import os
from datetime import timedelta
from urllib.parse import urlsplit


READ_TOOLS = {
    "get_proxy_http_history",
    "get_proxy_http_history_regex",
    "get_scanner_issues",
    "get_organizer_items",
    "get_organizer_items_regex",
    "get_proxy_websocket_history",
    "get_proxy_websocket_history_regex",
    "get_project_options",
    "get_user_options",
    "get_active_editor_contents",
    "url_encode",
    "url_decode",
    "base64_encode",
    "base64_decode",
}


def endpoint(url=None):
    from hydra.config import load_environment

    load_environment()
    value = url or os.getenv("BURP_MCP_URL") or "http://127.0.0.1:9876"
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Burp MCP must use an HTTP loopback endpoint; use an SSH tunnel for a remote Burp instance")
    return value.rstrip("/")


class BurpClient:
    def __init__(self, url=None, timeout=30):
        self.url = endpoint(url)
        self.timeout = timeout

    async def _exchange(self, name=None, arguments=None):
        try:
            import httpx
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError:
            raise ValueError("Install Burp MCP support: python -m pip install -r requirements-agent.txt") from None

        expected = urlsplit(self.url)

        async def check_request(request):
            actual = urlsplit(str(request.url))
            if (actual.scheme, actual.hostname, actual.port) != (expected.scheme, expected.hostname, expected.port):
                raise ValueError("Burp MCP attempted to use another origin")

        def http_client(**kwargs):
            return httpx.AsyncClient(
                **kwargs, trust_env=False, follow_redirects=False, event_hooks={"request": [check_request]}
            )

        async with sse_client(
            self.url, timeout=5, sse_read_timeout=self.timeout, httpx_client_factory=http_client
        ) as streams:
            async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=self.timeout)) as session:
                initialized = await session.initialize()
                tools = []
                cursor = None
                for _ in range(10):
                    page = await session.list_tools(cursor=cursor)
                    tools.extend(page.tools)
                    cursor = page.nextCursor
                    if not cursor:
                        break
                if name is None:
                    return {
                        "success": True,
                        "server": initialized.serverInfo.name,
                        "tools": [
                            {
                                "name": tool.name,
                                "description": (tool.description or "")[:1500],
                                "inputSchema": tool.inputSchema,
                            }
                            for tool in tools[:200]
                        ],
                    }
                selected = next((tool for tool in tools if tool.name == name), None)
                if selected is None:
                    raise ValueError("The connected Burp server does not expose this tool")
                from jsonschema import validate, ValidationError

                try:
                    validate(arguments, selected.inputSchema)
                except ValidationError:
                    raise ValueError("Arguments do not match the Burp tool's input schema") from None
                result = await session.call_tool(name, arguments)
                text = "\n".join(block.text for block in result.content if block.type == "text")
                return {
                    "success": not result.isError,
                    "tool": name,
                    "text": text[:32000],
                    "truncated": len(text) > 32000,
                }

    async def status(self):
        return await self.exchange()

    async def exchange(self, name=None, arguments=None):
        try:
            return await asyncio.wait_for(self._exchange(name, arguments), self.timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ValueError(
                "Burp MCP request failed. Check that Burp and its official MCP extension are running at "
                + self.url
                + "; verify the tool name and arguments with burp_tools."
            ) from None

    async def call(self, name, arguments, *, approve, read_only=False):
        if not isinstance(name, str) or not name or not isinstance(arguments, dict):
            raise ValueError("Burp requires a tool name and an arguments object")
        if read_only and name not in READ_TOOLS:
            raise PermissionError("This Burp tool is unavailable in read-only mode")
        if len(json.dumps(arguments)) > 32000:
            raise ValueError("Burp arguments exceeded 32 KB")
        allowed = approve(["burp-mcp", name, json.dumps(arguments, ensure_ascii=False)])
        if inspect.isawaitable(allowed):
            allowed = await allowed
        if not allowed:
            raise PermissionError("Burp tool execution was denied")
        return await self.exchange(name, arguments)
