# HYDRA engineering runtime

HYDRA is being expanded into a general-purpose engineering agent. The new
runtime is an implemented foundation, not a claim of feature parity with or
superiority to AlphaCode. Existing authorized security workflows remain available.

## Start

```powershell
.\setup.ps1
.\run.ps1 doctor --workspace .
.\run.ps1 run "Explain the architecture and identify likely maintenance risks" --workspace . --read-only
.\run.ps1 run "Fix the failing tests with the smallest correct change" --workspace . --provider ollama
.\run.ps1 chat --workspace . --provider ollama
```

`python -m hydra` is the unified entry point. Use `hydra security --help` for
security workflows or `hydra engineering --help` for the explicit engineering
entry. Existing engineering commands remain unchanged. Recognized old security
flags are forwarded to the security adapter; `python -m hydra.main` remains a
compatibility launcher. See [ARCHITECTURE.md](ARCHITECTURE.md).

The agent needs a reachable model. Set a provider locally in `.env` using the
existing `OLLAMA_URL`, `OLLAMA_MODEL`, `CUSTOM_LLM_URL`, `CUSTOM_LLM_MODEL`,
`CUSTOM_LLM_KEY`, `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` settings. Never paste
credentials into chat or source control. `doctor` reports configured providers
and checks Ollama reachability without printing API keys. An explicitly selected
provider is isolated so a failed request is not silently routed elsewhere.

For the expanded AlphaCode-derived provider catalog, use `hydra providers` and
see [PROVIDERS.md](PROVIDERS.md). Use `--provider openai-api` for API-key OpenAI;
`openai` in the parity catalog refers to subscription/OAuth, which is pending.
`--model` selects an exact model/deployment without editing global settings.

Live OpenCode catalog discovery succeeded; attempted free inference was refused
with HTTP 403 and a minimal paid-model request required account billing (HTTP 402).
No successful live engineering task has been verified. Offline regression tests
use a deterministic model fixture while exercising real filesystem changes,
real Python subprocesses, failed/passing assertions, session reload and rollback.
Those tests verify orchestration, not model intelligence or benchmark superiority.

## What is implemented

- A bounded inspect → plan → act → verify loop using structured JSON actions.
- Workspace listing, literal search, bounded UTF-8 reading, exact replacement,
  atomic writes, content-hash conflict detection, and tracked unified diffs.
- Enforcement that root and nested `AGENTS.md` files are read before editing.
- Workspace boundaries that reject parent paths, symlinks/junctions, private-key
  files, environment secrets and internal session/dependency directories.
- Operator-approved argv-based process execution, timeouts, process-tree cleanup
  and bounded retained output. No shell-string interpolation is used.
- Persistent sessions with version checks, SHA-256 integrity, atomic checkpoints,
  write-ahead original file contents, conflict-aware rollback, and resume.
- A completion gate: tracked edits or arbitrary commands require a successful
  configured verification after the last modification before `finish` is accepted.
- An interactive terminal loop with follow-ups in the same session.
- Hard model/action-step and elapsed-time limits, plus bounded protocol/failure
  retries. These are execution limits, **not financial spending limits**.
- [AI-EOS V5 phase 1](AI_EOS_V5.md): strict existing-session validation, per-run
  tool/context/failure limits, observed-token ceilings, recorded stop reasons and
  evidence-linked handoff exports.

## Permissions and verification

File tools stay within the workspace. **An approved command has your normal OS
permissions and is not sandboxed**; it can access paths and the network beyond
the workspace. Read its argv before authorizing. The default prompts for every
command and denies commands in non-interactive execution. `--allow-run` explicitly
authorizes those commands without individual prompts. `--read-only` disables
both file changes and command execution.

Verification can be detected from Python tests, Cargo.toml, go.mod or an npm test
script. Override it with a JSON array, for example:

```powershell
.\run.ps1 run "Fix addition" --workspace E:\projects\calculator --provider ollama `
  --verify-command '["python","-m","pytest","-q"]' --max-steps 30 --max-seconds 600
```

Auto-detection for Python uses the interpreter running HYDRA. Set an explicit
verification command if the target project uses a different virtual environment.
Command approval is required for verification too. Successful exit status only
establishes that the selected check passed; choose meaningful acceptance tests.

## Inspect and recover

```powershell
.\run.ps1 sessions --workspace E:\projects\calculator
.\run.ps1 sessions --show SESSION_ID --workspace E:\projects\calculator
.\run.ps1 diff SESSION_ID --workspace E:\projects\calculator
.\run.ps1 resume SESSION_ID --workspace E:\projects\calculator --provider ollama
.\run.ps1 rollback SESSION_ID --workspace E:\projects\calculator
```

Sessions live in `.hydra/sessions/` inside the selected workspace. They contain
original file contents, action arguments and retained tool output: keep them
private and out of source control. Resume rechecks permissions; `--allow-run` is
not inherited. Rollback affects tracked file-tool edits only, never arbitrary
command side effects. It refuses to overwrite subsequent user edits. Snapshots
and hashes protect against accidental corruption, not an attacker with write
access to the same account. Concurrent stale saves fail instead of overwriting.
Do not run the same session concurrently. A crash during a snapshot save can
leave a `.lock`; inspect it before removing it and resuming.

## Remaining work toward the AlphaCode goal

1. Verify real provider runs and establish task success/repair-rate benchmarks
   on the same tasks, models, hardware and budgets as the comparison baseline.
2. Add streaming native tool calls, tokenizer-aware request reservations and
   financial cost accounting. Observed-token and context-character limits exist;
   they do not enforce a monetary cap. The current tool protocol uses JSON text.
3. Build Git worktree integration, semantic/LSP navigation and
   stronger OS-level execution isolation.
4. Add general engineering delegation and desktop automation with
   capability-specific permissions and integration tests.
5. Expose security tooling as an optional capability pack; avoid mixing its
   network-scope rules with local repository editing permissions.

The opt-in [browser capability](BROWSER.md) is wired into the engineering runtime
and tested in isolated Chromium. Desktop and general multi-agent capabilities
remain unavailable in this runtime.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_engineering_agent.py -q
.\.venv\Scripts\python.exe -m pytest tests -q
```
