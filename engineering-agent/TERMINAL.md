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
python -m pip install -r requirements-agent.txt
python -m hydra tui --workspace /path/to/project --provider ollama --model YOUR_MODEL
```

For a fresh checkout on Linux/macOS with Python 3.10+ and venv:

```sh
cd engineering-agent
bash setup.sh --skip-tests
bash run.sh
```

Setup installs the terminal, HTTP provider transports, AWS SDK and Burp MCP client
into `.venv`. API keys/account access, locally hosted model downloads, Burp Suite
and its extension are configured separately. The legacy security-tool installer
is preserved as `setup-security.sh`; engineering setup does not require root.

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
| `/model` or `/models` | Open the searchable provider/model table |
| `/model MODEL_ID` | Change the model for the current provider |
| Ctrl+F in model dialog | Toggle favorite for the highlighted row or entered model |
| Ctrl+O in model dialog | Save a default model for future launches |
| `/provider NAME MODEL` | Select an implemented provider/model |
| `/burp` | Check the Burp MCP server and list its tools |
| `/status` | Show the selected session's run limits, usage and stop reason |
| `/handoff` | Show a validated handoff of committed session state |
| `/cancel` / Ctrl+C | Cancel the active run |
| `/help` | Show supported commands |
| `/quit` / Ctrl+Q | Exit |

Model changes apply to the next request, including a follow-up in the current
session. Finish or cancel an active run before changing models. The model table
starts with configured/saved IDs. **Refresh list** fetches the selected provider's
live catalog with its own credentials, without sending project context or an
inference prompt. Providers without a model-list endpoint can use manual entry.
A catalog listing does not guarantee your account can run that model.
Search filters provider/model IDs; Enter in search focuses the table, and Enter
on a row applies it. Escape cancels. Favorites and the explicit default are stored
in your user configuration directory (`hydra/models.json`), without API keys.
Launch flags override a saved default. Unimplemented subscription/OAuth profiles
remain unavailable; they are not labelled as working OAuth routes.

Burp MCP is built in; see [BURP.md](BURP.md) for its extension and connection setup.

Run limits apply to this interface too: `--max-tool-calls`, `--max-tokens`,
`--max-context-chars` and `--max-failures`. Token limits use observed provider
counts and can exceed by one in-flight request; they are not spending caps.
See [AI_EOS_V5.md](AI_EOS_V5.md) for the exact limits and phased roadmap.

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
