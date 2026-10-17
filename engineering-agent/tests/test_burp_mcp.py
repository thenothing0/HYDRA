"""Exercise actual MCP SSE initialization, discovery and calls against a local fixture."""

import asyncio
import json
from uuid import uuid4

import pytest
import pytest_asyncio
from aiohttp import web

pytest.importorskip("mcp")
from hydra.engineering.burp import BurpClient, endpoint
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


@pytest_asyncio.fixture
async def burp_server():
    queues = {}
    calls = []
    requests = []

    async def sse(request):
        requests.append(request.path)
        ident = uuid4().hex
        queue = queues[ident] = asyncio.Queue()
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        await response.write(f"event: endpoint\ndata: /messages?session_id={ident}\n\n".encode())
        try:
            while True:
                message = await queue.get()
                if message is None:
                    break
                await response.write(("event: message\ndata: " + json.dumps(message) + "\n\n").encode())
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        return response

    async def post(request):
        message = await request.json()
        method = message["method"]
        if "id" not in message:
            return web.Response(status=202)
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "burp-fixture", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "get_proxy_http_history",
                        "description": "Read local fixture history",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"count": {"type": "integer"}},
                            "required": ["count"],
                        },
                    }
                ]
            }
        elif method == "tools/call":
            calls.append(message["params"])
            result = {"content": [{"type": "text", "text": "Recorded fixture request"}], "isError": False}
        else:
            result = {}
        await queues[request.query["session_id"]].put({"jsonrpc": "2.0", "id": message["id"], "result": result})
        return web.Response(status=202)

    app = web.Application()
    app.router.add_get("/", sse)
    app.router.add_post("/messages", post)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", calls, requests
    for queue in queues.values():
        await queue.put(None)
    await runner.cleanup()


@pytest.mark.asyncio
async def test_burp_handshake_tool_discovery_and_approved_read(burp_server, tmp_path):
    url, calls, _ = burp_server
    tools = EngineeringTools(
        Session(Workspace(tmp_path), goal="Inspect fixture traffic"),
        burp_url=url,
        approve_burp=lambda request: True,
        read_only=True,
    )
    assert "burp_call" in tools.available_tools
    status = await tools.execute("burp_status", {})
    assert status["server"] == "burp-fixture"
    assert status["tools"][0]["name"] == "get_proxy_http_history"
    result = await tools.execute("burp_call", {"name": "get_proxy_http_history", "arguments": {"count": 1}})
    assert result["success"]
    assert "Recorded fixture" in result["text"]
    assert calls[0]["arguments"] == {"count": 1}


@pytest.mark.asyncio
async def test_denial_and_read_only_block_before_any_network(burp_server):
    url, calls, requests = burp_server
    client = BurpClient(url)
    with pytest.raises(PermissionError, match="denied"):
        await client.call("get_proxy_http_history", {"count": 1}, approve=lambda _: False)
    with pytest.raises(PermissionError, match="read-only"):
        await client.call("send_http1_request", {}, approve=lambda _: True, read_only=True)
    assert not calls and not requests


@pytest.mark.asyncio
async def test_invalid_burp_schema_never_calls_tool(burp_server):
    url, calls, _ = burp_server
    with pytest.raises(ValueError):
        await BurpClient(url).call("get_proxy_http_history", {"count": "invalid"}, approve=lambda _: True)
    assert not calls


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example",
        "http://192.0.2.1:9876",
        "http://user:pass@127.0.0.1:9876",
        "http://127.0.0.1:9876?key=secret",
    ],
)
def test_burp_endpoint_must_be_loopback_without_credentials(url):
    with pytest.raises(ValueError, match="loopback"):
        endpoint(url)
