"""Provider transport contracts use local HTTP servers, never paid endpoints."""
import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.providers import CATALOG, ProviderModel, ProviderSettings, registry, settings, validate_url
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


@pytest.mark.parametrize("provider", [p["id"] for p in CATALOG["profiles"]])
def test_every_api_profile_builds_request_with_own_credentials(monkeypatch, provider):
    profile = registry()[provider]
    prefix = provider.upper().replace("-", "_")
    monkeypatch.setenv(prefix + "_BASE_URL", "http://127.0.0.1:18090/v1")
    for key in ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "CUSTOM_LLM_URL", "OLLAMA_URL"):
        monkeypatch.setenv(key, "http://127.0.0.1:18090/v1")
    if profile["key_env"]:
        monkeypatch.setenv(profile["key_env"], "fixture-key-" + provider)
    config = settings(provider, "fixture-model")
    model = ProviderModel(provider)
    model.config = config
    url, headers, payload = model.request("fixture input")
    assert url.startswith("http://127.0.0.1:18090/")
    assert payload["model"] == "fixture-model"
    assert payload.get("input", payload.get("prompt", payload.get("messages", [{}])[0].get("content"))) == "fixture input"
    if profile["requires_key"]:
        assert "fixture-key-" + provider in str(headers)
    assert config.api_key not in repr(config) if config.api_key else True


def test_catalog_accounts_for_all_upstream_login_entries():
    ids = {p["id"] for p in CATALOG["login_catalog"]}
    assert len(ids) == 60
    assert ids.issubset(registry())
    assert registry()["copilot"]["status"] == "auth_integration_pending"


def test_minimax_never_borrows_openai_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-shared")
    monkeypatch.delenv("MINIMAX_API_KEY", raising=False)
    with pytest.raises(ValueError, match="MINIMAX_API_KEY"):
        settings("minimax", "fixture-model")


def test_oauth_only_entry_is_not_falsely_activated():
    with pytest.raises(ValueError, match="not implemented"):
        settings("copilot", "fixture-model")


@pytest.mark.parametrize("url", ["http://remote.example/v1", "https://user:secret@example.com/v1",
                                 "https://example.com/v1?key=secret", "file:///tmp/api"])
def test_unsafe_provider_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_url(url)


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["responses", "anthropic", "ollama", "openai_chat"])
async def test_real_http_transport_and_token_accounting(protocol):
    seen = []
    async def handler(request):
        seen.append((request.path, dict(request.headers), await request.json()))
        text = '{"tool":"finish","arguments":{"summary":"inspected"}}'
        if protocol == "responses":
            body = {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
                    "usage": {"input_tokens": 7, "output_tokens": 8}}
        elif protocol == "anthropic":
            body = {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 7, "output_tokens": 8}}
        elif protocol == "ollama":
            body = {"response": text, "prompt_eval_count": 7, "eval_count": 8}
        else:
            body = {"choices": [{"message": {"content": text}}], "usage": {"prompt_tokens": 7, "completion_tokens": 8}}
        return web.json_response(body)
    app = web.Application()
    app.router.add_post("/{tail:.*}", handler)
    async with TestServer(app) as server:
        model = ProviderModel()
        model.config = ProviderSettings("fixture", protocol, str(server.make_url("/v1")).rstrip("/"), "fixture", "not-a-real-key")
        result = await model.respond("inspect repository")
        assert json.loads(result)["tool"] == "finish"
        assert model.usage == {"requests": 1, "input_tokens": 7, "output_tokens": 8}
    path, headers, body = seen[0]
    if protocol == "responses":
        assert path == "/v1/responses" and body["store"] is False
    if protocol == "anthropic":
        assert headers["x-api-key"] == "not-a-real-key"
        assert "Authorization" not in headers


@pytest.mark.asyncio
async def test_provider_never_follows_credential_redirects():
    async def redirect(request):
        return web.Response(status=302, headers={"Location": "https://unrelated.invalid"})
    app = web.Application()
    app.router.add_post("/chat/completions", redirect)
    async with TestServer(app) as server:
        model = ProviderModel()
        model.config = ProviderSettings("fixture", "openai_chat", str(server.make_url("/")).rstrip("/"), "fixture", "private-fixture")
        with pytest.raises(RuntimeError, match="HTTP 302") as error:
            await model.respond("request")
        assert "private-fixture" not in str(error.value)


@pytest.mark.asyncio
async def test_engineering_agent_uses_actual_provider_http_protocol(tmp_path, monkeypatch):
    async def handler(request):
        body = await request.json()
        assert body["messages"][0]["role"] == "system"
        assert json.loads(body["messages"][-1]["content"])["goal"] == "Explain fixture"
        return web.json_response({"choices": [{"message": {"content": json.dumps({
            "tool": "finish", "arguments": {"summary": "Read-only fixture task completed"}})}}]})
    app = web.Application()
    app.router.add_post("/v1/chat/completions", handler)
    async with TestServer(app) as server:
        monkeypatch.setenv("CUSTOM_LLM_URL", str(server.make_url("/v1")).rstrip("/"))
        monkeypatch.setenv("CUSTOM_LLM_MODEL", "fixture")
        model = ProviderModel("custom")
        await model.initialize()
        session = Session(Workspace(tmp_path), "Explain fixture")
        result = await EngineeringAgent(session, model, EngineeringTools(session, read_only=True)).run()
        assert result["status"] == "completed"
        assert result["provider"] == "openai-compatible"
        assert result["model_usage"]["requests"] == 1


@pytest.mark.asyncio
async def test_http_agent_repairs_code_and_verifies_actual_subprocess(tmp_path, monkeypatch):
    import sys
    from hydra.engineering.workspace import digest
    original = b"def add(a, b):\n    return a - b\n"
    (tmp_path / "calc.py").write_bytes(original)
    calls = 0
    async def handler(request):
        nonlocal calls
        calls += 1
        body = await request.json()
        context = json.loads(body["messages"][-1]["content"])
        if calls == 1:
            action = {"tool": "read_file", "arguments": {"path": "calc.py"}}
        elif calls == 2:
            action = {"tool": "verify", "arguments": {}}
        elif calls == 3:
            assert context["recent_events"][-1]["result"]["exit_code"] == 1
            action = {"tool": "edit_file", "arguments": {"path": "calc.py", "old": "a - b",
                      "new": "a + b", "expected_sha256": digest(original)}}
        elif calls == 4:
            action = {"tool": "verify", "arguments": {}}
        else:
            assert context["verified_revision"] == context["revision"] == 1
            action = {"tool": "finish", "arguments": {"summary": "Addition repaired and regression check passed"}}
        return web.json_response({"choices": [{"message": {"content": json.dumps(action)}}]})
    app = web.Application()
    app.router.add_post("/v1/chat/completions", handler)
    async with TestServer(app) as server:
        monkeypatch.setenv("CUSTOM_LLM_URL", str(server.make_url("/v1")).rstrip("/"))
        monkeypatch.setenv("CUSTOM_LLM_MODEL", "test-fixture-not-a-real-model")
        model = ProviderModel("custom")
        await model.initialize()
        session = Session(Workspace(tmp_path), "Fix addition")
        tools = EngineeringTools(session, approve=lambda argv: True,
                                 verify_command=[sys.executable, "-B", "-c", "from calc import add; assert add(2,3)==5"])
        result = await EngineeringAgent(session, model, tools).run()
    assert result["status"] == "completed" and calls == 5
    assert b"a + b" in (tmp_path / "calc.py").read_bytes()


def test_azure_uses_deployment_and_resource_endpoint(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "fixture")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "my-deployment")
    config = settings("azure")
    assert config.base_url == "https://example.openai.azure.com/openai/v1"
    assert config.model == "my-deployment"


@pytest.mark.asyncio
async def test_bedrock_real_sdk_contract_without_aws_network(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from types import SimpleNamespace
    sdk_session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    client = sdk_session.client("bedrock-runtime")
    stub = Stubber(client)
    stub.add_response("converse", {
        "output": {"message": {"role": "assistant", "content": [{"text": "fixture response"}]}},
        "stopReason": "end_turn", "usage": {"inputTokens": 7, "outputTokens": 8, "totalTokens": 15},
        "metrics": {"latencyMs": 1},
    }, {"modelId": "fixture.model", "messages": [{"role": "user", "content": [{"text": "fixture request"}]}],
        "inferenceConfig": {"maxTokens": 4096}})
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: SimpleNamespace(client=lambda *args, **kw: client))
    model = ProviderModel()
    model.config = ProviderSettings("bedrock", "bedrock", "", "fixture.model")
    with stub:
        assert await model.respond("fixture request") == "fixture response"
        stub.assert_no_pending_responses()
    assert model.usage == {"requests": 1, "input_tokens": 7, "output_tokens": 8}
