# HYDRA — General-purpose software engineering agent

[![Engineering CI](https://github.com/thenothing0/HYDRA/actions/workflows/hydra-engineering.yml/badge.svg)](https://github.com/thenothing0/HYDRA/actions/workflows/hydra-engineering.yml)
[![Security platform CI](https://github.com/thenothing0/HYDRA/actions/workflows/ci.yml/badge.svg)](https://github.com/thenothing0/HYDRA/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

HYDRA inspects repositories, plans changes, edits files, runs approved commands,
verifies results and saves resumable sessions. Its interactive terminal brings
chat, model selection, tool activity, plans and diffs into one workspace.
Browser inspection and Burp MCP extend the same engineering workflow.

**Status:** an actively developed engineering agent with tested tools and recovery
controls. Model quality and feature parity with AlphaCode have not been established.
The current runtime lives in **[`engineering-agent/`](engineering-agent/README.md)**;
run the setup and launch commands below from that directory.

## Quick start

Install **Git and Python 3.10+ with `venv`** first. You also need access to a
supported hosted provider or a running local model service.

### Linux

```sh
git clone https://github.com/thenothing0/HYDRA.git
cd HYDRA/engineering-agent
bash setup.sh --skip-tests
bash run.sh
```

On Debian/Ubuntu, install `python3-venv` if Python cannot create the environment.
The Linux installer is exercised in CI. The shell scripts also support macOS,
but macOS execution has not been verified here.

### Windows PowerShell

```powershell
git clone https://github.com/thenothing0/HYDRA.git
cd HYDRA\engineering-agent
.\setup.ps1 -SkipTests
.\run.ps1
```

Setup creates `.venv`, installs the terminal, HTTP provider transports, AWS SDK
and Burp MCP client, and creates `.env` from `.env.example` when it is absent.
Existing `.env` settings are preserved. Omit `--skip-tests` / `-SkipTests` to
install development dependencies and run the test suite during setup.

Provider keys belong in **`engineering-agent/.env`** or environment variables.
Setup does not supply account access or credits, download local models, or install
Burp Suite and its extension. External security tools are configured separately.

Choose your provider and exact model in the terminal, or launch explicitly:

```sh
bash run.sh tui --workspace /path/to/project --provider ollama --model YOUR_MODEL
```

```powershell
.\run.ps1 tui --workspace E:\projects\app --provider ollama --model YOUR_MODEL
```

Ollama must already be running with the selected model installed. For a hosted
provider, use its profile ID and local credentials; see [provider setup](engineering-agent/PROVIDERS.md).

## Interactive terminal

Type a task, review tool activity and approve commands when prompted. Plans,
tracked diffs and saved sessions are available alongside the conversation.
**Enter** submits, **Ctrl+J** inserts a newline, **Ctrl+C** cancels the active run
and **Ctrl+Q** exits after cleanup.

| Command | Action |
| --- | --- |
| `/model` | Open the searchable provider/model table |
| `/provider NAME MODEL` | Select an implemented provider and model |
| `/new` | Start a new session |
| `/sessions` / `/resume SESSION_ID` | Browse or resume saved work |
| `/plan` / `/diff` | Inspect the plan or tracked file changes |
| `/burp` | Check the Burp MCP connection and discover its tools |
| `/status` | Show run limits, usage and stop reason |
| `/handoff` | Display a validated export of committed session state |
| `/cancel` / `/quit` | Cancel work or exit |

The `/model` dialog supports search, favorites (**Ctrl+F**), a saved default
(**Ctrl+O**) and **Refresh list** for the selected provider's live catalog.
Manual model IDs remain available when a provider has no catalog endpoint.
A listed model still needs account access. Model changes apply to the next request.

See [terminal setup and shortcuts](engineering-agent/TERMINAL.md).

## Engineering tools and recovery

- Search and read workspace files; apply hash-checked edits and atomic writes.
- Respect root and nested `AGENTS.md` rules and guard secret/internal paths.
- Run approved commands with deadlines and bounded retained output.
- Require verification before completing tracked code changes.
- Save integrity-checked sessions, resume work and roll back tracked file edits
  while refusing conflicts with subsequent changes.
- Inspect explicitly paired browser tabs and keep scoped investigation evidence.

For scripts and headless use, the same runtime exposes these commands from
`engineering-agent/` on Linux; use `.\run.ps1` instead of `bash run.sh` on Windows:

```sh
bash run.sh doctor
bash run.sh providers
bash run.sh run "Explain this repository" --workspace /path/to/project --read-only
bash run.sh run "Fix the failing tests" --workspace /path/to/project --provider deepseek --model YOUR_MODEL
bash run.sh sessions --workspace /path/to/project
bash run.sh diff SESSION_ID --workspace /path/to/project
bash run.sh resume SESSION_ID --workspace /path/to/project --provider ollama --model YOUR_MODEL
bash run.sh rollback SESSION_ID --workspace /path/to/project
bash run.sh handoff SESSION_ID --workspace /path/to/project > handoff.json
```

Approved commands run with normal OS permissions. Rollback covers tracked
file-tool edits; arbitrary command side effects require separate recovery.
See the [engineering guide](engineering-agent/ENGINEERING.md) and
[architecture](engineering-agent/ARCHITECTURE.md).

## Provider support

The catalog tracks **60 entries** from the inspected AlphaCode revision:
**51 transport profiles are implemented**, while **nine subscription/OAuth
integrations remain pending**. Supported transports include OpenAI Responses,
Anthropic Messages, Gemini's compatible API, Ollama, compatible HTTP APIs, Azure
and AWS Bedrock. Transport tests do not certify every hosted service or account.

**OpenCode check, 2026-10-17:** live catalog discovery returned 48 models.
Free-model inference returned `403 FreeTierError`; a paid-model request returned
`402` for account credits/billing. No successful live OpenCode engineering task
is claimed. See the [provider matrix, routes and live-test details](engineering-agent/PROVIDERS.md).

## Burp MCP and browser extension

**Burp MCP is a built-in capability.** Install the official Burp MCP extension
separately, enable its server and run `/burp`. The default loopback SSE endpoint
is `http://127.0.0.1:9876`; configure `BURP_MCP_URL` locally if it differs.
Every Burp tool call requires approval, including reads. `--allow-run` does not
bypass Burp approval. Protocol tests use a local MCP server; a live Burp GUI has
not been verified here. See [Burp setup](engineering-agent/BURP.md).

The optional browser extension loads through Chrome/Edge **Developer mode →
Load unpacked**. It supports paired-tab inspection, scoped interactions and
passive network metadata. A Firefox development build is also available;
temporary installation and signing limits are documented, and live Firefox
behavior remains unverified. See [browser setup](engineering-agent/BROWSER.md).
Use security workflows only with explicit authorization for the target scope.

## AI-EOS V5 implementation

Phase 1 adds validated durable state, independent per-run limits, failure
budgets, correlated audit events and evidence-linked handoff exports.
The default run allows 30 model steps and 600 seconds. CLI and terminal options
include `--max-tool-calls`, `--max-tokens`, `--max-context-chars` and `--max-failures`.

Token limits use reported usage and may cross the ceiling by one in-flight
request; they are not financial spending caps. Context limits count characters.
Project memory, richer capability policies, task benchmarks and optional
delegation remain later phases. See [implemented behavior and roadmap](engineering-agent/AI_EOS_V5.md)
and the [machine-readable phase record](engineering-agent/EOS_V5_STATUS.json).

## Verification and current limits

The 2026-10-17 local engineering-suite snapshot was **723 passed, nine skipped**.
Engineering CI passed on Python 3.10, 3.11 and 3.12, including the Linux installer.
Tests cover real file/process operations, verification, recovery, terminal
interactions, local HTTP/MCP transports and governance. Fixture results measure
implementation behavior, not live model quality. Check the CI badges for the
current branch status.

To run the engineering suite on Linux after setup:

```sh
cd engineering-agent  # from the repository root
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -q
```

On Windows, use `.venv\Scripts\python.exe` for both commands. Native model-token
streaming, subscription/OAuth login, OS isolation, financial budgets and broad
task-success benchmarking remain development work. See
[implementation status](engineering-agent/ENGINEERING_STATUS.json).

## Repository and documentation

| Location | Purpose |
| --- | --- |
| [`engineering-agent/`](engineering-agent/README.md) | Current engineering runtime, installers, terminal, tools and tests |
| [`engineering-agent/TERMINAL.md`](engineering-agent/TERMINAL.md) | Interactive workflow and model selection |
| [`engineering-agent/PROVIDERS.md`](engineering-agent/PROVIDERS.md) | Provider configuration and authentication status |
| [`engineering-agent/BURP.md`](engineering-agent/BURP.md) | Burp MCP connection and approvals |
| [`engineering-agent/BROWSER.md`](engineering-agent/BROWSER.md) | Chromium/Firefox extension setup |
| [`engineering-agent/AI_EOS_V5.md`](engineering-agent/AI_EOS_V5.md) | Implemented V5 foundations and next phases |
| [`SECURITY_PLATFORM_LEGACY.md`](SECURITY_PLATFORM_LEGACY.md) | Archived root README for the separate security/knowledge platform |

The root `hydra/`, `mcp_server.py`, `wiki/` and associated platform tests belong
to the legacy security/knowledge system. Its documentation and contribution
invariants remain relevant to that system. Engineering commands above use the
runtime inside `engineering-agent/`.

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). License: [MIT](LICENSE).
