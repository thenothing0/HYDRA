# HYDRA review — 2026-10-16

This records the security-runtime review before the general engineering extension.
It is a historical record; see [ARCHITECTURE.md](ARCHITECTURE.md) for the later
runtime split, lazy configuration and deployment-default corrections.
For the newer runtime and its current limits see `ENGINEERING.md`,
`ENGINEERING_STATUS.json` and `output/engineering-tests.xml`.

Scope: Python CLI, scope enforcement at the execution boundary, HTTP tool
server, Windows setup, dependencies, existing offline tests and local startup.
The two bundled Omarchy trees were excluded. No external target was scanned.

## Fixed

| Finding | Change / evidence |
| --- | --- |
| Windows setup could accept a failing Python alias, install globally, suppress failures and still announce completion | Project-local `.venv`, interpreter validation, checked subprocess exit codes, reproducible launcher |
| `.env` was created by setup but never loaded by configuration | Load project `.env` before environment-derived defaults; process variables take precedence; isolated subprocess regression test |
| Scope refusals crashed the summary printer | Error summaries now print clearly; CLI exits 1 instead of `KeyError` |
| A loaded scope with no authorized assets allowed arbitrary targets | Empty allowlist now fails closed |
| CLI tool layer did not receive the loaded scope policy | Engine attaches scope before initialization |
| Logical aliases / explicit tool overrides could evade forbidden-tool policy | Check the resolved binary and every supplied stdin/list target before spawning |
| Tool arguments were modified in-place | Copy arguments so retries retain original values |
| Timed-out or cancelled tools could continue running | Kill and reap the direct child process |
| HTTP execution constructor defaulted to no scope gate and all-interface binding | Fail closed and bind to loopback by default; Docker still explicitly overrides its internal bind |
| Malformed JSON object shapes / timeouts produced server errors | Validate request shape and respond 400; integration tests use a real local aiohttp test server |
| Target names could create nested / parent output paths on Windows | Sanitize output directory component; traversal regression cases |
| Missing local input and failed external tools could appear successful | Local input error; record tool failures and mark all-tools-failed runs as failed |
| Source review traversed virtual environments | Exclude `.venv`, `venv`, caches and existing dependency directories |
| `--no-ai` did not control model enrichment/filtering | Skip semantic enrichment and optional ML filtering |
| Workflow display omitted hunt, confirm and swarm | Display all accepted CLI workflow names |
| Python HTTPX could be counted as ProjectDiscovery's scanner | Probe scanner `-version`; prioritize verified scanner binaries in launcher |
| Concurrent execution setting was not applied by the CLI tool server | Semaphore bounds active subprocesses; regression test verifies serialization |
| Stdio MCP failed with SDK 2.x and an unsupported FastMCP version keyword | Constrain SDK to 1.x, correct constructor; real stdio client verifies handshake/list/refusal |
| Installed Dirsearch rejected `--format=json`; ffuf had no default wordlist | Use supported `--output-formats=json`, verify its parser offline, and ship a small default wordlist |

## Verification

- Baseline: 514 passed, 9 skipped.
- After fixes: **535 passed, 9 skipped in 19.02 seconds**; results are recorded
  in `output/readiness-tests.xml`. The nine skips require optional PyTorch.
- JUnit evidence: `output/readiness-tests.xml`.
- `pip check`: no broken requirements.
- `compileall` passed for `hydra` and root MCP entry point.
- Local `code_review` smoke run generated JSON, Markdown and HTML reports under
  `output/readiness-smoke/hydra_config.py/reports/`.
- A broader offline source-review smoke run covered 99 HYDRA source files and
  produced 11 pattern matches under `output/readiness-audit/hydra/reports/`.
  Manual triage: four PyTorch `.eval()` calls, two string markers for forbidden
  execution, two TLS-rule string matches, and three non-security identifier
  hashes. These are not confirmed exploitable vulnerabilities; the matches
  illustrate the limits of the regex-based source reviewer.
- HTTP request validation, no-scope refusal and health endpoint are covered by
  local integration tests. No real network assessment was performed.
- Stdio MCP: real client initialization, listing tools and no-scope refusal passed.
- Installed 8/11 tools: wafw00f 2.4.2, dirsearch 0.5.0, subfinder 2.17.0,
  ProjectDiscovery httpx 1.12.0, nuclei 3.11.1, katana 1.8.0, ffuf 2.3.0,
  gau 2.2.4. All six downloaded Windows binaries started successfully with
  version-only arguments; SHA-256 verification also passed on repeated setup.
  Version logs and `tool-readiness.log` are stored in `output/`.

## Remaining limits

- This checkout has no `.git` directory, so a Git diff/commit is unavailable.
- Nmap, Amass and WhatWeb need separate platform-specific installation. Other
  Windows binaries can be installed by `install-tools.ps1`; inspect its manifests
  and `run.ps1 --check-tools` for the actual installed state.
- The large AI/ML stack is optional and was not installed or exercised; real API
  providers, model downloads and paid usage are not validated.
- The CLI parses `--budget` but does not wire that argument into a per-run cost
  tracker. Do not rely on it as an enforced financial limit.
- Dashboard code exists but the CLI does not start it; HTTP tool server exposes
  `/execute`, not `/scan`. Older README deployment examples overstate this wiring.
- Distributed workers construct their own local tool clients; coordinator scope
  validation is not a substitute for worker-side enforcement. Distributed mode
  needs a separate policy/transport review before use.
- Docker/Kubernetes were not built or started: Docker is unavailable here.
  Images use floating tool/dependency versions, Compose includes default database
  credentials and published service ports, and scaling uses a fixed worker
  container name. Treat those manifests as development scaffolding.
- Timeouts terminate the direct tool process, not an OS-enforced process tree.
- Scope checks cover explicit tool inputs; DNS resolution, redirects and tool
  crawler behavior require tool-specific containment for stronger isolation.
- Static source findings and scanner output are candidates, not proof of impact.
  README claims such as zero false positives / <2% FP were not established.

Local CLI readiness is verified. Production, distributed operation and real
target assessment readiness are not established by these offline checks.
