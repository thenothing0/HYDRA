# Running HYDRA locally on Windows

Run commands from the project directory (`E:\tools\src\src`).

```powershell
.\setup.ps1
.\run.ps1 security --list-workflows
.\run.ps1 security --check-tools
```

If `python` points to the Microsoft Store alias, setup also checks `py` and
per-user Python installations. You can select an interpreter explicitly:

```powershell
.\setup.ps1 -PythonExecutable 'C:\path\to\python.exe'
```

Setup creates `.venv`, installs core/test dependencies, creates `.env` only if
absent, checks dependency consistency, and runs the offline tests. Existing
environment variables override `.env`. No AI credentials are required for the
local CLI. `-Full` additionally installs `requirements.txt` (large optional AI,
vector database and infrastructure dependencies).

## External scanners

```powershell
.\setup.ps1 -InstallTools
```

This installs wafw00f/dirsearch inside `.venv` and official Windows x64 binaries
for subfinder, ProjectDiscovery httpx, nuclei, katana, ffuf and gau in `.tools/bin`.
Downloads are checked against the publisher's SHA-256 checksum file before
extracting the named executable. `.tools/*.json` records versions and hashes;
repeated setup reuses verified installations. `run.ps1` puts these binaries
before Python's unrelated `httpx` command on PATH. GitHub access is required.

Amass, Nmap and WhatWeb require separate platform-specific installation.
`--check-tools` lists what remains missing. Some workflows will have partial
results until those tools are available. Tool availability alone does not prove
scan effectiveness or validate templates against a real target.

## Offline source review

```powershell
.\run.ps1 security -t hydra/config.py -w code_review --no-ai --no-learn
```

`code_review` and `web3_audit` accept local paths and require no network scope.
Source review uses pattern matching, not a complete semantic or dependency audit.
Review findings manually. Results are written under `output/<target>/`.

## Authorized network scans

Create your own scope JSON with explicitly authorized assets:

```json
{
  "program": "my-authorized-program",
  "in_scope": [{"asset": "your-authorized-domain.example"}],
  "out_of_scope": [],
  "forbidden_testing": ["dos", "social_engineering"]
}
```

```powershell
.\run.ps1 -t your-authorized-domain.example -w quick_recon --scope-file scope.json --no-ai
```

No scope, an empty authorized asset list, or an out-of-scope target is refused.
If all attempted tools fail, the CLI exits with code 1. Partial failures are
listed in `reports/summary.json` with `status: partial`; do not interpret zero
findings as proof that the target is secure.

## Local HTTP tool server

```powershell
$env:PATH = "$PWD\.tools\bin;$PWD\.venv\Scripts;$env:PATH"
.\.venv\Scripts\python.exe -m hydra.mcp.http_server
```

The default binding is `127.0.0.1:8900`; `/health` and `/tools` are available.
`POST /execute` refuses execution without scope. Set `HYDRA_SCOPE_FILE` to your
authorized scope file before starting the server. Keep this unauthenticated
service local. It exposes tools, not the `/scan` API shown in older README examples.

## Stdio MCP for coding clients

```powershell
.\setup.ps1 -MCP
.\run-mcp.ps1
```

The launcher waits for a client on stdin. Setup also generates `.mcp.local.json`
with absolute interpreter/script paths and the scanner PATH; merge that server
entry into your client's MCP configuration. The original `.mcp.json` is a generic
example that assumes `python` is already on PATH. The server uses MCP SDK 1.x;
SDK 2.x renamed FastMCP and is intentionally excluded. Initialization, tool
listing and scope refusal are tested through a real stdio MCP client.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q -rs
.\.venv\Scripts\python.exe -m pip check
```

ML tests skip when PyTorch is absent. Docker/Kubernetes, Redis-backed workers,
model providers and actual network scanning require separate integration checks.
See `REVIEW.md` for the review scope and known limitations.

`requirements-local.lock.txt` records the packages in the verified local Windows
environment, including optional scanners and MCP dependencies; it is platform
specific. Use the smaller requirements files for a new minimal environment.
