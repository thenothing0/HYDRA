"""Real local HTTP catalog requests and credential-free preference storage."""

import json

import pytest
from aiohttp import web

from hydra.engineering.models import ModelPreferences, discover_models, local_models


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider,path,payload",
    [
        ("opencode", "/v1/models", {"data": [{"id": "test/model"}, {"id": "test/model"}]}),
        ("ollama", "/api/tags", {"models": [{"name": "local:latest"}]}),
        ("anthropic-api", "/v1/models", {"data": [{"id": "test-model"}]}),
    ],
)
async def test_model_discovery_protocols_and_auth(monkeypatch, provider, path, payload):
    observed = []

    async def models(request):
        observed.append(dict(request.headers))
        return web.json_response(payload)

    app = web.Application()
    app.router.add_get(path, models)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    from hydra.engineering.providers import ProviderSettings

    monkeypatch.setattr(
        "hydra.engineering.models.settings",
        lambda *_: ProviderSettings(
            provider,
            {"opencode": "openai_chat", "ollama": "ollama", "anthropic-api": "anthropic"}[provider],
            f"http://127.0.0.1:{port}" + ("" if provider == "ollama" else "/v1"),
            "unused",
            "private-fixture",
        ),
    )
    try:
        result = await discover_models(provider)
        assert len(result) == 1
        assert result[0]["provider"] == provider
        if provider == "anthropic-api":
            assert observed[0]["x-api-key"] == "private-fixture"
            assert "Authorization" not in observed[0]
        else:
            assert observed[0]["Authorization"] == "Bearer private-fixture"
        assert "private-fixture" not in json.dumps(result)
    finally:
        await runner.cleanup()


def test_model_preferences_roundtrip_and_local_catalog(tmp_path):
    path = tmp_path / "preferences.json"
    prefs = ModelPreferences(path)
    assert not path.exists()
    prefs.toggle("opencode", "my-model")
    prefs.set_default("opencode", "my-model")
    saved = ModelPreferences(path)
    assert saved.default == ("opencode", "my-model")
    rows = local_models([{"id": "opencode", "model": "configured"}], ("opencode", "my-model"), saved)
    assert {row["id"] for row in rows} == {"my-model", "configured"}
    assert set(json.loads(path.read_text())) == {"default", "favorites"}
    saved.toggle("opencode", "my-model")
    assert not ModelPreferences(path).favorites


def test_corrupt_preferences_are_recoverable(tmp_path):
    path = tmp_path / "preferences.json"
    path.write_text("[]")
    assert ModelPreferences(path).default is None
