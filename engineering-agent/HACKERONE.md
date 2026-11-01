# HackerOne reporting

HYDRA can submit a finding through the official **Hacker API** after all checks
in an operator-owned validation plan pass. This is an opt-in capability for one
program and structured asset at a time. It does not scan targets, guess a program,
or treat the model's confidence as proof of a vulnerability.

"Impact bounds" means the approved, nondestructive investigation has reached its
documented stopping point. No general automated check can prove that a finding's
impact can never increase. Keep observed impact, hypotheses and limitations distinct.

## Account setup

Run commands from `engineering-agent/` after the normal setup. The default
installer includes the HTTP client. Set these values in your local `.env`:

```dotenv
HACKERONE_USERNAME=your_hackerone_username
HACKERONE_API_TOKEN=your_personal_api_token
```

Use your HackerOne username and personal Hacker API token, not a customer API
account or browser cookie. Generate/revoke the token in your account settings;
do not paste it into chat or commit `.env`. See the official
[token instructions](https://docs.hackerone.com/en/articles/8410331-api-token).

Discover account-visible programs and select an actual structured scope ID:

```sh
bash run.sh hackerone programs --workspace /path/to/project
bash run.sh hackerone scopes PROGRAM_HANDLE --workspace /path/to/project
bash run.sh hackerone program PROGRAM_HANDLE --scope-id SCOPE_ID --workspace /path/to/project
```

Replace `PROGRAM_HANDLE`, `SCOPE_ID` and paths with real values. On Windows,
replace `bash run.sh` with `.\run.ps1`. Reading a program is not permission to
test every asset. Review its current policy, exclusions, selected asset
instructions, report template and required fields before authorizing submission.

## Authorize a validation plan

Keep the plan and trusted verification scripts **outside the agent workspace**.
Start from [the plan example](examples/hackerone-plan.example.json), replace its
paths/IDs, and set `expires_at` to a future ISO-8601 UTC timestamp within seven days.
The placeholder date intentionally makes the example inactive.
Copy `reviewed_snapshot_digest` from the `hackerone program` output only after
reviewing that snapshot. Authorization fetches it again and refuses a different
digest, binding the approval to the exact reviewed policy/asset/exclusions.

Every plan must contain these five checks exactly once:

| Check ID | Required decision in your verifier |
| --- | --- |
| `reproduction` | The final reproduction succeeds on the authorized asset using permitted accounts/data |
| `negative_control` | An independent baseline/control distinguishes the issue from expected behavior or a false positive |
| `impact` | Observed evidence supports the report's impact and severity; taxonomy is appropriate |
| `impact_bounds` | All permitted checks in this finding's investigation plan are complete; unresolved escalation hypotheses or unsafe steps are recorded and block readiness when necessary |
| `report_quality` | Target scope/exclusions, current template/custom requirements, redaction, reproducible steps and evidence are satisfied |

These are **finding-specific checks you supply**, not five built-in vulnerability
detectors. A script that simply exits zero does not establish these claims. HYDRA
enforces execution and successful exit; the verifiers must assess the actual
evidence and permitted investigation. They must not expand testing authorization.

Each check has fixed `argv`, one standalone `{finding}` argument, a timeout of
1–120 seconds and `pinned_files` for its trusted scripts/dependencies. HYDRA pins
the executable and listed file hashes; changing them requires reauthorization.
The executable, scripts and their trusted dependency chain must remain outside
model-writable code. Scripts receive a normalized JSON snapshot including the
redacted evidence text; read it as data and never execute its contents.

After reviewing the exact current program policy and the check implementations:

```sh
bash run.sh hackerone authorize --workspace /path/to/project --plan /path/to/operator/hackerone-plan.json --policy-reviewed
bash run.sh hackerone status --workspace /path/to/project
bash run.sh tui --workspace /path/to/project --hackerone
```

Authorization is bound to the API username, workspace and selected program/asset, expires within seven
days and permits 1–20 submission attempts; use one initially. The policy hash
includes the current program policy, selected scope, exclusions and weaknesses.
A later change blocks sending until the operator reviews and reauthorizes.

## Prepare and send

The agent can use `hackerone_status`, `hackerone_program` and `hackerone_submit`
when launched with `--hackerone`. `/hackerone` shows local configuration and
recent receipts without contacting the API. A model cannot authorize a plan or
enable the capability through tool arguments.

Create a finding JSON based on [the finding example](examples/hackerone-finding.example.json).
Use the exact asset identifier and an actual program weakness ID from the API;
a `weakness_id` is not necessarily its CWE number. Evidence must be UTF-8 text
files inside the workspace with matching SHA256 hashes, at most ten files of
32 KB each. Include only redacted requests/results for the intended program.
Do not copy production credentials or another program's private information.
The configured API token and obvious unredacted authentication/cookie headers
are refused, but this check is not comprehensive secret detection.

The submission tool runs the five fixed commands, refuses any denied, failed,
timed-out or missing check, rechecks evidence and the live program, then makes
one `POST /v1/hackers/reports`. The report includes reproduction steps,
expected/observed results, impact bounds, limitations and redacted text evidence.
It always includes an explicit supported severity rating. Structured-scope
**submission eligibility** is checked independently of bounty eligibility.

HTTP URL/domain/wildcard scopes are supported for automatic matching. The URL
must match the selected host, scheme/port/path where specified; other asset
types require a separate reviewed implementation. Policy-specific exclusions,
multiple interacting assets and template/custom requirements must also be
enforced by the finding's `report_quality` verifier. Unsupported API requirements
can still be rejected by HackerOne; local completeness does not guarantee acceptance.

For a prepared finding, the standalone equivalent is:

```sh
bash run.sh hackerone submit finding.json --workspace /path/to/project
```

Validation commands use the normal command approval flow. `--allow-run` can
approve these fixed commands for an invocation, including `tui --hackerone
--allow-run`; it cannot create a reporting policy, add a check, change its
target or bypass the reporting gates. A valid policy already grants the final
submission, so no further report confirmation is requested after the checks.
Read-only sessions cannot run checks or submit. Burp calls still require their
separate approval, and enabling this integration does not authorize new scanning.

## Receipts, retries and boundaries

State is saved under the workspace's protected `.hydra/hackerone/` directory:
the authorized plan, normalized finding snapshots, check digests and report
receipts. Successful receipts include the report ID/link. Add `.hydra/` to
your project's ignore rules and do not share its private evidence.

A workspace lock prevents concurrent submissions. A fingerprint of the program,
scope, endpoint, weakness and root cause prevents repeated sending of the same
finding, including after a title/severity edit. This does not discover duplicates
submitted elsewhere or establish that a finding is new to the program.

Before the POST, a durable `sending` receipt is written. A timeout, cancellation,
server error or uncertain response produces `unknown`; process death can leave
`sending`. Neither state is automatically retried. Inspect your HackerOne
reports before reconciling local state. Definite rejections such as 422/429 are
also retained without automatic retry; correct the cause and review the failed
submission manually. The HTTP client refuses redirects and environment proxies,
limits response sizes and withholds raw error bodies and credentials.

Verifier commands run with your normal OS permissions. This is not process
isolation; a separately approved command can access local files, including
reporting state. File-tool guards and hashes are not protection against an
attacker controlling your OS account. Tracked-file rollback cannot retract an
external report. There is no background scheduler or unattended target scanner.

## Verification

```sh
python -m pytest tests/test_hackerone_reporting.py tests/test_engineering_tui.py -q
```

Tests run real local subprocess validators and record HTTP requests through an
in-memory API transport. They cover allowed submission, failures, scope/policy
changes, evidence/verifier mutation, approval denial, cancellation, concurrency,
expiry, budgets, redirects and duplicate prevention. No live HackerOne report
has been submitted or account access verified by these tests.

API contract reviewed on 2026-11-01:
[Hacker resources](https://api.hackerone.com/hacker-resources/),
[authentication/errors](https://api.hackerone.com/getting-started-hacker-api/).
