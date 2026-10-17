"""Real loopback HTTP/WebSocket transport; extension messages are test fixtures."""
import asyncio
import json

import pytest
from aiohttp import ClientSession, WSMsgType
from aiohttp.test_utils import TestClient, TestServer

from hydra.browser.bridge import BrowserBridge, origin, clean_url
from hydra.browser.investigation import InvestigationStore
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


@pytest.mark.parametrize("url,expected", [
    ("https://example.com:443/path?q=secret", "https://example.com"),
    ("http://localhost:8080/path", "http://localhost:8080"),
    ("http://[::1]:8000/", "http://[::1]:8000"),
])
def test_origin_normalization(url, expected):
    assert origin(url) == expected
    assert "secret" not in clean_url(url)


@pytest.mark.parametrize("url", ["file:///tmp/private", "chrome://settings", "https://user:password@example.com", "javascript:alert(1)"])
def test_non_web_and_embedded_credentials_are_rejected(url):
    with pytest.raises(ValueError):
        origin(url)


def test_empty_scope_refuses_start(tmp_path):
    with pytest.raises(ValueError):
        BrowserBridge(tmp_path, [])


@pytest.mark.asyncio
async def test_auth_origin_and_mutation_gates(tmp_path):
    bridge = BrowserBridge(tmp_path, ["https://example.com"], token="fixture-secret")
    async with TestClient(TestServer(bridge.app)) as client:
        assert (await client.get("/health")).status == 200
        assert (await client.post("/command", json={"action": "tabs"})).status == 403
        assert (await client.post("/command", json={"action": "tabs"}, headers={
            "Authorization": "Bearer fixture-secret", "Origin": "https://evil.example"})).status == 403
        assert (await client.get("/extension", headers={"Origin": "https://evil.example"})).status == 403
        result = await client.post("/command", headers={"Authorization": "Bearer fixture-secret"},
                                   json={"action": "click", "arguments": {"tab_id": 1, "selector": "#button"}})
        assert result.status == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("extension_origin", ["chrome-extension://" + "a" * 32,
    "moz-extension://12345678-1234-1234-1234-123456789abc"])
async def test_real_websocket_command_roundtrip_and_evidence_integrity(tmp_path, extension_origin):
    bridge = BrowserBridge(tmp_path, ["https://example.com"], token="fixture-secret")
    async with TestClient(TestServer(bridge.app)) as client:
        async with client.ws_connect("/extension", headers={"Origin": extension_origin}) as ws:
            await ws.send_json({"token": "fixture-secret"})
            assert (await ws.receive_json())["type"] == "paired"
            pending = asyncio.create_task(client.post("/command", headers={"Authorization": "Bearer fixture-secret"},
                json={"action": "snapshot", "arguments": {"tab_id": 7}}))
            command = await ws.receive_json()
            assert command["action"] == "snapshot" and command["arguments"]["tab_id"] == 7
            await ws.send_json({"id": command["id"], "result": {"url": "https://example.com/page?token=secret", "text": "Observed page", "elements": [], "forms": []}})
            response = await pending
            assert response.status == 200
            result = await response.json()
            saved = InvestigationStore(tmp_path).evidence(result["evidence_id"])
            assert saved["data"]["url"] == "https://example.com/page"
            assert saved["sha256"] == result["evidence_sha256"]


@pytest.mark.asyncio
async def test_wrong_token_is_not_paired(tmp_path):
    bridge = BrowserBridge(tmp_path, ["https://example.com"], token="fixture-secret")
    async with TestClient(TestServer(bridge.app)) as client:
        async with client.ws_connect("/extension", headers={"Origin": "chrome-extension://" + "a" * 32}) as ws:
            await ws.send_json({"token": "wrong"})
            message = await ws.receive()
            assert message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED)
            assert bridge.socket is None


@pytest.mark.asyncio
async def test_out_of_scope_browser_response_is_not_retained(tmp_path):
    bridge = BrowserBridge(tmp_path, ["https://example.com"], token="fixture-secret", allow_actions=True)
    async with TestClient(TestServer(bridge.app)) as client:
        async with client.ws_connect("/extension", headers={"Origin": "chrome-extension://" + "a" * 32}) as ws:
            await ws.send_json({"token": "fixture-secret"})
            await ws.receive_json()
            pending = asyncio.create_task(client.post("/command", headers={"Authorization": "Bearer fixture-secret"},
                json={"action": "snapshot", "arguments": {"tab_id": 7}}))
            command = await ws.receive_json()
            await ws.send_json({"id": command["id"], "result": {"url": "https://outside.example/private", "text": "must not be retained"}})
            assert (await pending).status == 400
            assert not bridge.evidence_dir.exists()
            response = await client.post("/command", headers={"Authorization": "Bearer fixture-secret"},
                json={"action": "navigate", "arguments": {"tab_id": 7, "url": "https://outside.example"}})
            assert response.status == 400


def test_investigation_uses_real_evidence_and_never_promotes_differences(tmp_path):
    bridge = BrowserBridge(tmp_path, ["https://example.com"], token="fixture-secret")
    connection = tmp_path / ".hydra/browser/connection.json"
    connection.parent.mkdir(parents=True)
    connection.write_text(json.dumps({"origins": ["https://example.com"]}))
    store = InvestigationStore(tmp_path)
    case = store.create("https://example.com/items", "authorization", "Check owned test-account role behavior")
    baseline = bridge.record("snapshot", {"url": "https://example.com/items", "text": "Role A view", "elements": [], "forms": []})
    variant = bridge.record("snapshot", {"url": "https://example.com/items", "text": "Role B view", "elements": [], "forms": []})
    store.observe(case["id"], [baseline["evidence_id"]], "A view was observed; access-control impact is unverified")
    comparison = store.compare(case["id"], baseline["evidence_id"], variant["evidence_id"])
    assert comparison["classification"] == "observed_difference"
    report = store.report()
    assert report["confirmed_vulnerabilities"] == 0
    assert report["cases"][0]["methods"]
    with pytest.raises((ValueError, FileNotFoundError)):
        store.observe(case["id"], ["f" * 32], "invented evidence")
    evidence_path = bridge.evidence_dir / (baseline["evidence_id"] + ".json")
    corrupted = json.loads(evidence_path.read_text())
    corrupted["data"]["text"] = "changed"
    evidence_path.write_text(json.dumps(corrupted))
    with pytest.raises(ValueError, match="integrity"):
        store.report()


def test_browser_tools_are_opt_in_and_read_only_denies_interactions(tmp_path):
    session = Session(Workspace(tmp_path))
    disabled = EngineeringTools(session)
    assert "browser_snapshot" not in disabled.available_tools
    with pytest.raises(PermissionError):
        asyncio.run(disabled.execute("browser_tabs", {}))
    readonly = EngineeringTools(session, browser=True, read_only=True, allow_browser_actions=True)
    with pytest.raises(PermissionError):
        asyncio.run(readonly.execute("browser_click", {"tab_id": 1, "selector": "#button"}))
