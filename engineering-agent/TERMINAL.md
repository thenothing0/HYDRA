# HYDRA interactive terminal

The engineering runtime has a chat-first terminal interface inspired by
AlphaCode's workflow. It uses HYDRA's real tools, sessions and verification
gates. It does not reuse AlphaCode's code or imply feature/benchmark parity.

## Start

Run from this `engineering-agent` directory, rather than the repository's legacy
platform root:

```powershell
.\setup.ps1
.\run.ps1
```

Explicit startup with a model and target workspace:

```powershell
.\run.ps1 tui --workspace E:\projects\app --provider ollama --model YOUR_MODEL
```

For an existing minimal environment, install the optional interface first:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-tui.txt
```

Linux/macOS with an existing Python environment:

```sh
python -m pip install -r requirements-tui.txt
python -m hydra tui --workspace /path/to/project --provider ollama --model YOUR_MODEL
```

No-argument `python -m hydra` opens the interface. Existing headless commands
remain available. `python -m hydra tui --help` lists the launch options without
opening the interface. Credentials come from your local environment or `.env`;
there is no secret-key entry field, and keys are never requested in chat.

## Workflow

- Choose a provider and exact model at the top. “Configured” describes local
  settings, not a verified live connection. A model request is sent only when
  you submit a task. Pending native login profiles are not selectable.
- Enter submits a task; Ctrl+J inserts a newline. Tool notes and observed results
  appear in the conversation. This streams activity/results, not native model
  tokens; the provider protocol still returns complete JSON actions.
- Side panels show recent sessions, the current plan and tracked changes. Narrow
  terminals hide optional panels; shortcuts can bring them back.
- Commands and verification ask for **Allow once / Deny**. Deny is focused by
  default; Escape denies. `--allow-run` explicitly enables automatic command
  approval. `--read-only` still prevents writes and process execution.
- Ctrl+C cancels and saves an interrupted session. Ctrl+Q quits after cancellation
  cleanup. Select an unfinished session and choose **Resume selected** to
  continue it. Completed sessions can be inspected or continued with a new goal.

| Shortcut or command | Action |
| --- | --- |
| Ctrl+B / `/sessions` | Show saved sessions |
| Ctrl+D / `/diff` | Inspect tracked changes |
| Ctrl+N / `/new` | Start a new session |
| `/plan` | Show the current plan |
| `/resume SESSION_ID` | Resume an unfinished session |
| `/provider NAME MODEL` | Select an implemented provider/model |
| `/cancel` / Ctrl+C | Cancel the active run |
| `/help` | Show supported commands |
| `/quit` / Ctrl+Q | Exit |

The CLI's `--browser`, `--allow-browser-actions`, `--verify-command`, `--max-steps`
and `--max-seconds` options also apply. Browser use still requires the separately
paired local bridge; see [BROWSER.md](BROWSER.md). Token usage is displayed when
reported by the provider. Monetary budgets and OS-level isolation are not enforced.

## Validation and preview

Headless Textual tests exercise resizing, real guarded file edits and verification
processes, approval denial, cancellation before execution, session resume and
terminal control-sequence sanitization. Models are deterministic fixtures; these
tests require no paid API or external target.

```sh
python -m pytest tests/test_engineering_tui.py -q
python tools/preview_terminal.py
```

The preview uses the real UI, a temporary calculator project and a fixture model,
performs a local edit/check, and writes SVGs under `output/tui-preview`. Temporary
project data is removed afterward. It demonstrates interactions, not model quality.
