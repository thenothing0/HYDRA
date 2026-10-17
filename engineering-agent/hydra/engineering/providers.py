"""Provider-specific transport and explicit compatibility status. No credential reuse."""
import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp


CATALOG = json.loads(Path(__file__).with_name("provider_catalog.json").read_text(encoding="utf-8"))


def registry():
    profiles = {p["id"]: dict(p) for p in CATALOG["profiles"]}
    # Never send an OpenAI key to a third-party host merely because an upstream
    # profile happened to reuse that environment variable.
    profiles["minimax"]["key_env"] = "MINIMAX_API_KEY"
    profiles["openai-api"].update(protocol="responses", model_env="OPENAI_MODEL")
    profiles["anthropic-api"].update(protocol="anthropic", model_env="ANTHROPIC_MODEL")
    profiles["gemini-api"]["model_env"] = "GEMINI_MODEL"
    profiles["ollama"].update(protocol="ollama", base_url="http://127.0.0.1:11434", model_env="OLLAMA_MODEL")
    profiles["opencode"]["base_url"] = "https://opencode.ai/inference/openai/v1"
    # An unspecified custom endpoint must not silently send project data to a
    # hosted proxy. The operator supplies its URL explicitly.
    profiles["openai-compatible"].update(base_url="", key_env="CUSTOM_LLM_KEY", model_env="CUSTOM_LLM_MODEL")
    profiles["agentrouter-anthropic"] = {
        "id": "agentrouter-anthropic", "name": "AgentRouter Anthropic", "base_url": "https://agentrouter.org",
        "key_env": "AGENTROUTER_API_KEY", "model_env": "AGENTROUTER_ANTHROPIC_MODEL",
        "requires_key": True, "protocol": "anthropic", "status": "implemented"}
    profiles["azure"] = {"id": "azure", "name": "Azure OpenAI", "base_url": "",
                         "key_env": "AZURE_OPENAI_API_KEY", "model_env": "AZURE_OPENAI_DEPLOYMENT",
                         "requires_key": True, "protocol": "responses", "status": "implemented"}
    profiles["bedrock"] = {"id": "bedrock", "name": "AWS Bedrock", "base_url": "",
                           "key_env": "", "model_env": "BEDROCK_MODEL", "requires_key": False,
                           "protocol": "bedrock", "status": "implemented_optional_sdk"}
    for entry in CATALOG["login_catalog"]:
        if entry["id"] not in profiles:
            profiles[entry["id"]] = {**entry, "status": "auth_integration_pending",
                                      "protocol": None, "model_env": "", "key_env": "", "requires_key": False}
    return profiles


def validate_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Provider base URL must be HTTP(S), with no credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Remote providers require HTTPS; plaintext is allowed only on loopback")
    return url.rstrip("/")


@dataclass
class ProviderSettings:
    id: str
    protocol: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    max_tokens: int = 4096
    timeout: int = 60


def settings(provider=None, model=None):
    # Load project .env using existing configuration, without importing secrets
    # into persistent provider metadata or session state.
    from hydra.config import load_environment
    load_environment()
    aliases = {"anthropic": "anthropic-api", "custom": "openai-compatible"}
    name = provider or os.getenv("HYDRA_PROVIDER", "")
    if not name:
        name = next((p for p, key in (("openai-api", "OPENAI_API_KEY"),
                                     ("anthropic-api", "ANTHROPIC_API_KEY"),
                                     ("gemini-api", "GEMINI_API_KEY"),
                                     ("openai-compatible", "CUSTOM_LLM_URL")) if os.getenv(key)), "ollama")
    name = aliases.get(name, name)
    profile = registry().get(name)
    if profile is None:
        raise ValueError(f"Unknown provider: {name}. Run hydra providers")
    if profile["status"] == "auth_integration_pending":
        raise ValueError(f"{name}: subscription/OAuth integration is not implemented; use its API-key alternative if available")
    prefix = re.sub(r"[^A-Z0-9_]", "_", name.upper())
    base_url = os.getenv(prefix + "_BASE_URL", profile["base_url"])
    if name == "openai-api":
        base_url = os.getenv("OPENAI_BASE_URL", base_url)
    if name == "anthropic-api":
        base_url = os.getenv("ANTHROPIC_BASE_URL", base_url)
    if name == "ollama":
        base_url = os.getenv("OLLAMA_URL", base_url)
    if name == "openai-compatible":
        base_url = os.getenv("CUSTOM_LLM_URL", base_url)
    if name == "azure":
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
        base_url = base_url or (endpoint + "/openai/v1" if endpoint else "")
    selected_model = model or os.getenv(profile["model_env"], "")
    # Preserve existing three provider defaults; other models are operator chosen.
    if not selected_model and name in ("openai-api", "anthropic-api", "ollama"):
        config_name = {"openai-api": "openai", "anthropic-api": "anthropic", "ollama": "ollama"}[name]
        from hydra.config import DEFAULT_MODELS
        selected_model = DEFAULT_MODELS[config_name]
    if not selected_model:
        raise ValueError(f"Set {profile['model_env']} or pass --model for {name}")
    key = os.getenv(profile["key_env"], "") if profile["key_env"] else ""
    protocol = profile["protocol"]
    if name == "opencode":
        # OpenCode publishes separate native routes. Explicit operator settings
        # cover models with provider-specific protocol requirements.
        default_protocol = ("gemini" if selected_model.startswith("gemini-") else
                            "anthropic" if selected_model.startswith("claude-") else
                            "responses" if selected_model.startswith(("gpt-", "grok-", "muse-")) else "openai_chat")
        protocol = os.getenv("OPENCODE_PROTOCOL", default_protocol)
        if protocol not in {"anthropic", "responses", "openai_chat", "gemini"}:
            raise ValueError("OPENCODE_PROTOCOL must be anthropic, responses, openai_chat or gemini")
        if selected_model.startswith("jev-"):
            raise ValueError("OpenCode's Jev/SystemOne models are not generative coding models; select another model")
        if not os.getenv("OPENCODE_BASE_URL"):
            family = "anthropic" if protocol == "anthropic" else "openai"
            base_url = ("https://opencode.ai/inference/google/v1beta" if protocol == "gemini" else
                        f"https://opencode.ai/inference/{family}/v1")
    if profile["requires_key"] and not key:
        raise ValueError(f"Set {profile['key_env']} locally for {name}")
    if profile["protocol"] != "bedrock":
        if not base_url:
            raise ValueError(f"Set {prefix}_BASE_URL / the provider endpoint before using {name}")
        base_url = validate_url(base_url)
    return ProviderSettings(name, protocol, base_url, selected_model, key)


def describe_providers():
    from hydra.config import load_environment
    load_environment()
    result = []
    for name, profile in registry().items():
        item = {k: profile.get(k) for k in ("id", "name", "protocol", "status", "key_env", "model_env")}
        try:
            resolved = settings(name)
            item.update(configured=True, model=resolved.model, base_url=resolved.base_url)
        except ValueError as error:
            item.update(configured=False, reason=str(error))
        result.append(item)
    return result


class ProviderModel:
    def __init__(self, provider=None, model=None):
        self.provider = provider
        self.model = model
        self.config = None
        self.usage = {"input_tokens": 0, "output_tokens": 0, "requests": 0}
        self.usage_available = False

    async def initialize(self):
        self.config = settings(self.provider, self.model)
        if self.config.protocol == "bedrock":
            try:
                import boto3  # noqa: F401
            except ImportError:
                raise ValueError("Bedrock needs the optional SDK: pip install -r requirements-providers.txt") from None

    def request(self, prompt):
        cfg = self.config
        instructions, separator, context = prompt.partition("SESSION DATA:\n")
        if not separator:
            instructions, context = "", prompt
        messages = ([{"role": "system", "content": instructions}] if instructions else []) + [
            {"role": "user", "content": context}]
        headers = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        if cfg.protocol == "gemini":
            from urllib.parse import quote

            headers.pop("Authorization", None)
            headers["x-goog-api-key"] = cfg.api_key
            body = {"contents": [{"role": "user", "parts": [{"text": context}]}],
                    "generationConfig": {"maxOutputTokens": cfg.max_tokens}}
            if instructions:
                body["systemInstruction"] = {"parts": [{"text": instructions}]}
            return cfg.base_url + "/models/" + quote(cfg.model, safe="") + ":generateContent", headers, body
        if cfg.protocol == "responses":
            body = {"model": cfg.model, "input": context, "max_output_tokens": cfg.max_tokens, "store": False}
            if instructions:
                body["instructions"] = instructions
            return cfg.base_url + "/responses", headers, body
        if cfg.protocol == "anthropic":
            headers.pop("Authorization", None)
            headers.update({"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"})
            body = {"model": cfg.model, "messages": [{"role": "user", "content": context}], "max_tokens": cfg.max_tokens}
            if instructions:
                body["system"] = instructions
            return cfg.base_url + ("/messages" if cfg.base_url.endswith("/v1") else "/v1/messages"), headers, body
        if cfg.protocol == "ollama":
            body = {"model": cfg.model, "prompt": context,
                "stream": False, "format": "json", "options": {"num_predict": cfg.max_tokens}}
            if instructions:
                body["system"] = instructions
            return cfg.base_url + "/api/generate", headers, body
        return cfg.base_url + "/chat/completions", headers, {
            "model": cfg.model, "messages": messages,
            "max_tokens": cfg.max_tokens, "stream": False}

    def parse(self, data):
        cfg = self.config
        usage = data.get("usage") or {}
        if not isinstance(usage, dict):
            usage = {}
        if cfg.protocol == "gemini":
            candidates = data.get("candidates", [])
            text = "".join(part.get("text", "") for candidate in candidates[:1]
                           for part in candidate.get("content", {}).get("parts", []) if not part.get("thought"))
            meta = data.get("usageMetadata", {})
            usage = {"input_tokens": meta.get("promptTokenCount"), "output_tokens": meta.get("candidatesTokenCount")}
        elif cfg.protocol == "responses":
            if data.get("status") not in (None, "completed"):
                raise RuntimeError(f"{cfg.id}: response was not complete")
            text = "".join(c.get("text", "") for item in data.get("output", [])
                           if item.get("type") == "message" for c in item.get("content", [])
                           if c.get("type") == "output_text")
        elif cfg.protocol == "anthropic":
            text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
        elif cfg.protocol == "ollama":
            text = data.get("response", "")
            usage = {"input_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count")}
        else:
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            text = content if isinstance(content, str) else "".join(c.get("text", "") for c in (content or []))
        input_count = usage.get("input_tokens", usage.get("prompt_tokens"))
        output_count = usage.get("output_tokens", usage.get("completion_tokens"))
        self.usage_available = all(type(value) is int and value >= 0 for value in (input_count, output_count))
        if self.usage_available:
            self.usage["input_tokens"] += input_count
            self.usage["output_tokens"] += output_count
        if not text:
            raise RuntimeError(f"{cfg.id}: provider returned no text")
        return text

    async def respond(self, prompt):
        if self.config.protocol == "bedrock":
            return await self._bedrock(prompt)
        url, headers, body = self.request(prompt)
        async with aiohttp.ClientSession() as client:
            async with client.post(url, json=body, headers=headers, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=self.config.timeout)) as response:
                if response.status >= 300:
                    # Do not log response bodies or URLs containing account data.
                    if response.status == 402:
                        raise RuntimeError(f"{self.config.id}: HTTP 402; the provider requires account credits or billing")
                    if self.config.id == "opencode" and response.status == 403:
                        try:
                            error_data = await response.json()
                            error_type = error_data.get("error", {}).get("type")
                        except (ValueError, AttributeError, TypeError):
                            error_type = None
                        if error_type == "FreeTierError":
                            raise RuntimeError("opencode: HTTP 403; this free tier is restricted to OpenCode's own client. Choose a supported paid model.")
                    raise RuntimeError(f"{self.config.id}: HTTP {response.status}; check credentials, model and endpoint")
                data = await response.json()
        self.usage["requests"] += 1
        return self.parse(data)

    async def _bedrock(self, prompt):
        import boto3
        from botocore.config import Config
        session = boto3.Session(profile_name=os.getenv("AWS_PROFILE") or None)
        client = session.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"),
                                config=Config(connect_timeout=5, read_timeout=self.config.timeout, retries={"max_attempts": 0}))
        try:
            data = await asyncio.to_thread(client.converse, modelId=self.config.model,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": self.config.max_tokens})
        finally:
            client.close()
        self.usage["requests"] += 1
        usage = data.get("usage", {})
        self.usage_available = all(type(usage.get(key)) is int and usage[key] >= 0
                                   for key in ("inputTokens", "outputTokens"))
        if self.usage_available:
            self.usage["input_tokens"] += usage["inputTokens"]
            self.usage["output_tokens"] += usage["outputTokens"]
        text = "".join(c.get("text", "") for c in data.get("output", {}).get("message", {}).get("content", []))
        if not text:
            raise RuntimeError("bedrock: provider returned no text")
        return text
