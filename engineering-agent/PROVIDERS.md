# Provider compatibility and authentication status

This catalog tracks all **60** login/provider entries in AlphaCode commit
`b2969e969ccfa7eeff0cff3d9e1f7c706387b52d`:
[upstream metadata](https://github.com/dragonked2/alphacode/blob/b2969e969ccfa7eeff0cff3d9e1f7c706387b52d/src/alphacode_provider_metadata/catalog.rs).
Public endpoint/environment-variable facts are retained in
`hydra/engineering/provider_catalog.json`, with provenance. No credentials,
embedded upstream API keys, subscription tokens or auth caches are imported.

## What works at the transport level

The catalog contains 48 API profiles. HYDRA adds dedicated AgentRouter Anthropic,
Azure OpenAI and optional AWS Bedrock transports, giving 51 transport profiles.
Native subscription/OAuth entries are tracked separately rather than silently
mapped to API-key billing.

```powershell
.\run.ps1 providers
.\run.ps1 providers --json
.\run.ps1 doctor
.\run.ps1 run "Review this project" --workspace E:\projects\app --provider deepseek --model YOUR_MODEL_ID --read-only
```

**Transport implemented does not mean account access or live compatibility has
been verified.** Tests validate every API profile's request construction and
exercise real local HTTP exchanges for the four protocol families. No successful
paid-model inference has been verified here. Provider availability,
model access and third-party proxy-specific requirements can change.

The API profiles are: opencode, opencode-go, zai, kimi, 302ai, baseten, cortecs,
tokenharbor, openrouter, anthropic-api, openai-api, gemini-api, deepseek, comtegra,
fpt, firmware, huggingface, moonshotai, nebius, scaleway, stackit, groq, mistral,
perplexity, togetherai, deepinfra, fireworks, minimax, xai, lmstudio, ollama,
dragonmeta, gmicloud, chutes, zerog, cerebras, alibaba-coding-plan, alphax-free,
nvidia-nim, xiaomi-mimo, celeris, agentrouter, tokenrouter, codecraft, unikey,
openai-compatible, unorouter and atria.

## Setup

Run `providers --json` to see the exact `key_env` and `model_env` names for each
profile. Put secrets in local `.env` or process environment variables. Most
providers require you to choose the model explicitly with `--model` or the
profile's model environment variable; the catalog's upstream reference models
are not advertised as current or automatically chosen.

Each profile supports a `<PROVIDER_ID_WITH_UNDERSCORES>_BASE_URL` override.
The existing `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `OLLAMA_URL` and
`CUSTOM_LLM_URL` names are also supported. Remote endpoints require HTTPS;
plain HTTP is restricted to loopback. Redirects are refused so credentials are
not automatically forwarded to a different endpoint. An explicitly selected
provider is never silently replaced by another provider.

Important differences:

- OpenAI API uses `/responses`; `openai-api` is distinct from pending `openai`
  subscription OAuth. [Official quickstart](https://developers.openai.com/api/docs/quickstart).
- Anthropic API uses Messages with `x-api-key` and `anthropic-version` headers.
- Gemini API uses Google's documented OpenAI-compatible endpoint and
  `GEMINI_API_KEY`; Google/Gemini OAuth is separate.
  [Official compatibility documentation](https://ai.google.dev/gemini-api/docs/openai).
- Ollama uses native `/api/generate`, JSON output mode and its reported token
  counts. LM Studio uses its compatible chat endpoint.
  [Ollama API](https://docs.ollama.com/api/generate).
- Azure needs `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY` and
  `AZURE_OPENAI_DEPLOYMENT`. The deployment name is the model parameter.
  [Microsoft documentation](https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/switching-endpoints).
- Bedrock needs `pip install -r requirements-providers.txt`, `BEDROCK_MODEL`,
  AWS credentials/profile and region. Its Converse call uses the AWS SDK's
  credential chain; do not put AWS secrets into source files. This optional SDK
  path is not live-account verified here.
  [Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html).
  Windows setup can install that optional SDK with `.\setup.ps1 -Providers`.
- MiniMax has a dedicated `MINIMAX_API_KEY`. HYDRA deliberately does not reuse
  OpenAI credentials for that third-party service.
- The generic compatible provider requires `CUSTOM_LLM_URL` explicitly; it does
  not send project context to the upstream catalog's default hosted proxy.
- `alphax-free` is a public endpoint profile, not a promise of free capacity or
  a copy of AlphaCode's private/free-pool credentials. It requires explicit
  selection and model configuration just like other transports.

## OpenCode live check and routes

OpenCode Console's current API has separate native routes for Responses, Messages,
Gemini and compatible Chat Completions. HYDRA selects GPT/Grok/Muse, Claude and
Gemini routes by model family; other models default to compatible chat. Set
`OPENCODE_PROTOCOL=anthropic|responses|gemini|openai_chat` for a model whose documented
route differs, and `OPENCODE_BASE_URL` for an explicit endpoint override. Model-list
discovery uses the separate catalog endpoint. Jev/SystemOne models are not general
text-generation models and cannot drive the engineering loop.

On 2026-10-17, a live catalog request returned 48 models. A live engineering smoke
test using `glm-5.3-flash-free` was refused with `FreeTierError`: the service limits
that free tier to its own client. A minimal paid-model request using `gpt-5.4-nano`
returned HTTP 402 (account credits/billing required). No successful live engineering
task is claimed. HYDRA does not spoof another client to bypass service restrictions.

After configuring a supported model and account credits locally, an opt-in check
can run on a temporary calculator project:

```sh
python tools/smoke_opencode.py --model YOUR_SUPPORTED_MODEL
```

It allows only its fixed regression command, checks the resulting edit and
verification, and removes the temporary project. It makes real provider requests;
normal account billing applies. See [OpenCode's model endpoints](https://opencode.ai/docs/zen/).

## Pending authentication integrations

The following entries are discoverable but **cannot be selected for inference**:
`claude`, `auto-import`, `alphacode`, `openai`, `cursor`, `copilot`, `gemini`,
`antigravity`, and `google`.

They require provider-specific OAuth/device flows, delegated CLI integrations
or an upstream service contract. No browser cookies, saved logins or unrelated
application credentials are scraped to make them appear enabled. API access
to Claude, OpenAI and Gemini is available through the separate API profiles.
Full authentication parity with AlphaCode has not been achieved.

## Usage and privacy

Provider-reported input/output token counts and request counts are saved in the
session. These are not a billing invoice or an enforced dollar budget. Session
state records the selected provider/model, not its API key. Configured providers
receive the goal and selected file/tool context. Review the endpoint and its
privacy policy before using hosted or third-party routes for private code.
