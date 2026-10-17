"""Provider model discovery and local model preferences, without credential storage."""

import json
import os
from pathlib import Path

import aiohttp

from hydra.engineering.providers import registry, settings
from hydra.engineering.workspace import atomic_write


def auth_method(provider):
    profile = registry()[provider]
    if profile["protocol"] == "bedrock":
        return "AWS SDK"
    return "API key" if profile["requires_key"] else "local"


class ModelPreferences:
    def __init__(self, path=None):
        base = Path(
            os.getenv("HYDRA_CONFIG_DIR")
            or os.getenv("XDG_CONFIG_HOME")
            or (Path(os.environ["APPDATA"]) if os.getenv("APPDATA") else Path.home() / ".config")
        )
        self.path = Path(path) if path else base / "hydra" / "models.json"
        self.default = None
        self.favorites = set()
        try:
            if self.path.stat().st_size > 128_000:
                raise ValueError("Model preferences are too large")
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.default = self.pair(data.get("default"))
            self.favorites = {pair for item in data.get("favorites", []) if (pair := self.pair(item))}
        except (OSError, ValueError, TypeError, AttributeError):
            self.default = None
            self.favorites = set()

    @staticmethod
    def pair(value):
        if (
            isinstance(value, (list, tuple))
            and len(value) == 2
            and all(isinstance(item, str) and 0 < len(item) <= 256 for item in value)
        ):
            return tuple(value)
        return None

    def save(self):
        atomic_write(
            self.path, json.dumps({"default": self.default, "favorites": sorted(self.favorites)}, indent=2).encode()
        )

    def toggle(self, provider, model):
        pair = (provider, model)
        if pair in self.favorites:
            self.favorites.remove(pair)
        else:
            self.favorites.add(pair)
        self.save()

    def set_default(self, provider, model):
        self.default = (provider, model)
        self.save()


def local_models(providers, current, preferences):
    supported = {p["id"] for p in providers}
    pairs = {(p["id"], p["model"]) for p in providers if p.get("model")}
    pairs.update(pair for pair in preferences.favorites if pair[0] in supported)
    if current[1]:
        pairs.add(tuple(current))
    return [
        {"provider": p, "id": m, "method": auth_method(p), "source": "saved"}
        for p, m in sorted(pairs)
        if p in supported
    ]


async def discover_models(provider):
    # Listing models does not need a configured inference model ID.
    config = settings(provider, "catalog-discovery")
    if config.protocol == "bedrock":
        raise ValueError("Enter an AWS deployment/inference profile manually; listing is not enabled for Bedrock")
    base = config.base_url
    headers = {}
    if config.api_key:
        headers["Authorization"] = "Bearer " + config.api_key
    if config.protocol == "anthropic":
        headers = {"x-api-key": config.api_key, "anthropic-version": "2023-06-01"}
        url = base + ("/models" if base.endswith("/v1") else "/v1/models")
    elif config.protocol == "ollama":
        url = base + "/api/tags"
    else:
        url = base + "/models"
    if provider == "opencode" and base.startswith("https://opencode.ai/inference/"):
        url = "https://opencode.ai/inference/v1/models"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), trust_env=False) as client:
        async with client.get(url, headers=headers, allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError(f"Model listing returned HTTP {response.status}; check provider configuration")
            payload = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                payload.extend(chunk)
                if len(payload) > 2_000_000:
                    raise ValueError("Provider model list exceeded 2 MB")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("Provider returned an invalid model list")
    rows = data.get("models" if config.protocol == "ollama" else "data", [])
    if not isinstance(rows, list):
        raise ValueError("Provider returned an invalid model list")
    ids = set()
    for row in rows[:2000]:
        if not isinstance(row, dict):
            continue
        ident = row.get("name" if config.protocol == "ollama" else "id")
        if isinstance(ident, str) and 0 < len(ident) <= 256 and not any(ord(c) < 32 for c in ident):
            ids.add(ident)
    return [
        {"provider": provider, "id": ident, "method": auth_method(provider), "source": "discovered"}
        for ident in sorted(ids)
    ]
