"""Authenticated loopback bridge. The extension owns all browser permissions."""
import asyncio
import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web, ClientSession, ClientTimeout, WSMsgType

from hydra.engineering.workspace import atomic_write


ACTIONS = {"tabs", "snapshot", "navigate", "click", "fill", "screenshot",
           "network_start", "network_stop", "network_events"}
MUTATIONS = {"navigate", "click", "fill"}


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Only HTTP(S) URLs without embedded credentials are supported")
    port = parsed.port
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and not default else "")


def clean_url(url):
    parsed = urlsplit(url)
    return origin(url) + (parsed.path or "/")  # no query values, credentials or fragment


class BrowserBridge:
    def __init__(self, workspace, allowed_origins, allow_actions=False, token=None):
        self.root = Path(workspace).resolve()
        for relative in (".hydra", ".hydra/browser", ".hydra/browser/evidence"):
            candidate = self.root / relative
            if (candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction())
                    or not candidate.resolve().is_relative_to(self.root)):
                raise ValueError("Browser storage must remain inside the workspace")
        self.origins = sorted({origin(value) for value in allowed_origins})
        if not self.origins:
            raise ValueError("At least one explicit authorized origin is required")
        self.allow_actions = allow_actions
        self.token = token or secrets.token_urlsafe(32)
        self.socket = None
        self.pending = {}
        self.lock = asyncio.Lock()
        self.evidence_dir = self.root / ".hydra/browser/evidence"
        self.app = web.Application(client_max_size=2_000_000)
        self.app.router.add_get("/health", self.health)
        self.app.router.add_get("/extension", self.extension)
        self.app.router.add_post("/command", self.command)
        self.app.on_cleanup.append(self.close)

    def authorized(self, request):
        supplied = request.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, "Bearer " + self.token)

    async def health(self, request):
        return web.json_response({"service": "hydra-browser", "connected": self.socket is not None and not self.socket.closed})

    async def extension(self, request):
        if not re.fullmatch(r"(?:chrome-extension://[a-p]{32}|moz-extension://[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})", request.headers.get("Origin", "")):
            raise web.HTTPForbidden(text="Extension origin required")
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=2_000_000)
        await ws.prepare(request)
        try:
            first = await asyncio.wait_for(ws.receive_json(), timeout=5)
            if not isinstance(first, dict) or not hmac.compare_digest(str(first.get("token", "")), self.token):
                await ws.close(code=1008, message=b"Pairing failed")
                return ws
            if self.socket is not None and not self.socket.closed:
                await ws.close(code=1008, message=b"An extension is already connected")
                return ws
            self.socket = ws
            await ws.send_json({"type": "paired", "origins": self.origins, "allow_actions": self.allow_actions})
            async for message in ws:
                if message.type != WSMsgType.TEXT:
                    continue
                try:
                    data = json.loads(message.data)
                    if data.get("type") == "ping":
                        await ws.send_json({"type": "pong"})
                        continue
                    future = self.pending.get(data.get("id"))
                    if future and not future.done():
                        future.set_result(data)
                except (ValueError, TypeError, AttributeError):
                    await ws.close(code=1008, message=b"Invalid message")
        except (asyncio.TimeoutError, ValueError, TypeError):
            await ws.close(code=1008, message=b"Pairing failed")
        finally:
            if self.socket is ws:
                self.socket = None
                for future in self.pending.values():
                    if not future.done():
                        future.set_exception(ConnectionError("Browser extension disconnected"))
        return ws

    def record(self, action, result):
        # Every returned URL must still belong to the authorized origin set.
        if action == "tabs":
            result = {"tabs": [tab for tab in result.get("tabs", []) if origin(tab["url"]) in self.origins]}
        elif result.get("url") and origin(result["url"]) not in self.origins:
            raise ValueError("Browser left authorized scope; result discarded")
        if result.get("url"):
            result["url"] = clean_url(result["url"])
        evidence = {"id": uuid.uuid4().hex, "action": action, "source": "paired-browser-extension",
                    "time": datetime.now(timezone.utc).isoformat(), "data": result}
        serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True).encode("utf-8")
        evidence["sha256"] = hashlib.sha256(serialized).hexdigest()
        atomic_write(self.evidence_dir / (evidence["id"] + ".json"),
                     json.dumps(evidence, ensure_ascii=False, indent=2).encode("utf-8"))
        # Screenshots remain local evidence rather than entering model context as base64.
        public = dict(result)
        if "image" in public:
            public["image"] = "Stored in local evidence; not included in model text"
        return {"evidence_id": evidence["id"], "evidence_sha256": evidence["sha256"], "result": public}

    async def command(self, request):
        if request.headers.get("Origin") or not self.authorized(request):
            raise web.HTTPForbidden(text="Local authenticated client required")
        try:
            body = await request.json()
            action = body.get("action")
            args = body.get("arguments", {})
            if action not in ACTIONS or not isinstance(args, dict):
                raise ValueError("Unknown browser action or invalid arguments")
            if action in MUTATIONS and not self.allow_actions:
                raise web.HTTPForbidden(text="Page interactions were not enabled by the operator")
            if action != "tabs" and (type(args.get("tab_id")) is not int or args["tab_id"] < 0):
                raise ValueError("A paired tab_id is required")
            if action == "navigate" and origin(args.get("url", "")) not in self.origins:
                raise ValueError("Navigation is outside authorized scope")
            if self.socket is None or self.socket.closed:
                raise web.HTTPServiceUnavailable(text="Pair the browser extension first")
            async with self.lock:  # avoid racing focus, navigation and captures
                ident = uuid.uuid4().hex
                future = asyncio.get_running_loop().create_future()
                self.pending[ident] = future
                try:
                    await self.socket.send_json({"id": ident, "action": action, "arguments": args})
                    response = await asyncio.wait_for(future, timeout=20)
                finally:
                    self.pending.pop(ident, None)
            if response.get("error"):
                return web.json_response({"error": response["error"]}, status=409)
            result = response.get("result")
            if not isinstance(result, dict):
                raise ValueError("Invalid browser response")
            return web.json_response(self.record(action, result))
        except (ValueError, TypeError, AttributeError, KeyError) as error:
            return web.json_response({"error": str(error)}, status=400)
        except (asyncio.TimeoutError, ConnectionError):
            return web.json_response({"error": "Browser command timed out or disconnected; inspect the tab before retrying interactions"}, status=504)

    async def close(self, app):
        if self.socket is not None:
            await self.socket.close()


class BrowserClient:
    def __init__(self, workspace):
        self.path = Path(workspace) / ".hydra/browser/connection.json"

    async def execute(self, action, arguments):
        if not self.path.is_file():
            raise ValueError("Start hydra browser start in this workspace and pair the extension")
        connection = json.loads(self.path.read_text(encoding="utf-8"))
        url = connection["url"]
        if urlsplit(url).scheme != "http" or origin(url).split("://", 1)[1].split(":", 1)[0] != "127.0.0.1":
            raise ValueError("Browser bridge must use IPv4 loopback")
        async with ClientSession() as client:
            async with client.post(url + "/command", json={"action": action, "arguments": arguments},
                    headers={"Authorization": "Bearer " + connection["token"]},
                    allow_redirects=False, timeout=ClientTimeout(total=25)) as response:
                if response.status >= 300:
                    raise ValueError(f"Browser bridge refused command (HTTP {response.status}): " + (await response.text())[:400])
                return await response.json()


async def serve(workspace, origins, port=8911, allow_actions=False):
    bridge = BrowserBridge(workspace, origins, allow_actions)
    runner = web.AppRunner(bridge.app, access_log=None)
    await runner.setup()
    connection = Path(workspace) / ".hydra/browser/connection.json"
    try:
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()
        actual_port = site._server.sockets[0].getsockname()[1]
        document = {"url": f"http://127.0.0.1:{actual_port}", "token": bridge.token, "origins": bridge.origins}
        atomic_write(connection, json.dumps(document, indent=2).encode("utf-8"))
        print(f"Browser bridge: {document['url']}\nPairing code (keep private): {bridge.token}", flush=True)
        print("Authorized origins:", ", ".join(bridge.origins), flush=True)
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
        if connection.exists():
            saved = json.loads(connection.read_text(encoding="utf-8"))
            if saved.get("token") == bridge.token:
                connection.unlink()
