# HYDRA Engineering

A general-purpose engineering agent under active development: inspect a repository,
plan a change, edit files, run authorized commands, verify the result, and resume
or roll back tracked work. The existing security platform remains available as a
separate capability pack.

**Current status:** a working engineering foundation, not established feature
parity with or superiority to AlphaCode. See [implementation status](ENGINEERING_STATUS.json).

The optional [browser extension](BROWSER.md) now supports paired-tab inspection,
scoped interactions, passive network metadata and evidence-based investigations.
Load it directly through Chrome/Edge Developer mode.

The [architecture guide](ARCHITECTURE.md) describes the unified CLI, session-local
capability registry, lazy configuration and the separated security components.

## Start on Windows

```powershell
.\setup.ps1
.\run.ps1 doctor
.\run.ps1 providers
.\run.ps1 chat --workspace E:\projects\app --provider ollama
```

Configure a reachable model locally first. No live model/account was configured
on the development machine; transport and orchestration tests use local fixtures.

For the interactive terminal, run `.\run.ps1` with no arguments or
`.\run.ps1 tui --workspace E:\projects\app`. It includes provider/model selection,
session navigation, live tool activity, plan/diff panels and command approval.
See [TERMINAL.md](TERMINAL.md) for setup, shortcuts and tested limits.

## Start on Linux/macOS

With Python 3.10+ and venv available, run from `engineering-agent`:

```sh
bash setup.sh --skip-tests
bash run.sh
```

The installer includes terminal, provider and Burp MCP client dependencies. API
keys/accounts, model downloads and external applications are configured separately.
`/model` opens a searchable model table with favorites, a saved default and live
provider catalog refresh. [Burp MCP](BURP.md) is a built-in capability; `/burp`
checks the official extension and its tools. Each Burp call needs approval.

```powershell
.\run.ps1 run "Fix the failing tests with a minimal change" --workspace E:\projects\app --provider deepseek --model YOUR_MODEL_ID
.\run.ps1 run "Explain the architecture" --workspace E:\projects\app --read-only
```

[Engineering guide](ENGINEERING.md) · [Provider configuration/status](PROVIDERS.md)

## Engineering capabilities

- Workspace search, bounded file reads, hash-checked edits, atomic writes and diffs.
- Root/nested AGENTS.md enforcement and guarded secret/internal paths.
- Approved local commands with timeouts and bounded retained output.
- Verification required before completing tracked code changes.
- Durable sessions with integrity checks, resume and conflict-aware file rollback.
- Explicit action/time limits and provider-reported token accounting.
- CLI task execution, interactive follow-ups, doctor and provider discovery.

Approved commands have normal OS permissions; this is not an OS sandbox.
Rollback covers tracked file-tool edits, not arbitrary command side effects.

## Providers

The parity catalog accounts for all 60 entries from the inspected AlphaCode commit.
There are 51 implemented transport profiles, including the 48 compatible API
profiles, native Responses/Messages/Ollama, AgentRouter Anthropic, Azure and optional
AWS Bedrock. The nine subscription/OAuth integrations remain explicitly pending.

Transport tests are not live account/service certification. No private upstream
credentials are copied, and one provider's API key is not borrowed for another.
See [the full matrix and limitations](PROVIDERS.md).

## Recovery

```powershell
.\run.ps1 sessions --workspace E:\projects\app
.\run.ps1 diff SESSION_ID --workspace E:\projects\app
.\run.ps1 resume SESSION_ID --workspace E:\projects\app --provider ollama
.\run.ps1 rollback SESSION_ID --workspace E:\projects\app
```

## Existing security workflows

Legacy flag-based commands still dispatch to the security engine:

```powershell
.\run.ps1 --check-tools
.\run.ps1 -t hydra/config.py -w code_review --no-ai --no-learn
```

Network assessments require explicit authorized scope. Read the reviewed
[security setup](RUNNING.md), [security review](REVIEW.md), and the archived
[security platform documentation](SECURITY_PLATFORM.md). Historical marketing
claims in the archived document are not newly verified engineering claims.

## Verification and next work

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q -rs
```

The implemented regressions cover real file/process changes, failed/passing
checks, resume, rollback, workspace policy and local HTTP provider transports.
The optional Bedrock contract is checked using the real SDK with Stubber, without
an AWS request. PyTorch-specific tests skip when its optional stack is absent.

Streaming native tool calls, richer TUI/Git integration, general delegation,
browser/desktop tools, OS isolation, financial budgets, native OAuth and matched
AlphaCode task benchmarks remain development work. See [ENGINEERING.md](ENGINEERING.md).

MIT licensed; see [LICENSE](LICENSE).
