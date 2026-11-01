# HYDRA skills

The engineering agent includes **300 imported security/OWASP skills** with their
**2,069 original resources**: entrypoints, procedures, field guides, templates,
offline helpers and UI metadata where supplied. The snapshot was imported on
2026-11-01 from the user's authored skills. Existing flat Markdown prompts and
the `web3-audit/` package remain available as legacy material; they are not
silently mixed into the new catalog.

## Terminal and CLI

Inside the interactive terminal:

```text
/skills xss
/skill security-xss-review
/skill security-finding-report
/skill clear
```

`/skills QUERY` searches names/descriptions; an empty query shows the first ten
entries. Search uses the English metadata terms and IDs. `/skill NAME` selects
instructions for this and subsequent tasks, while `/skill clear` clears the
active selection. Finish or cancel an active run before changing it manually.
Discovery/selection makes no model request and does not run a helper.

From `engineering-agent/` on Linux:

```sh
bash run.sh skills list
bash run.sh skills search "object authorization" --json
bash run.sh skills show security-xss-review
bash run.sh skills show security-xss-review references/investigation.md
bash run.sh tui --workspace /path/to/project --skill security-assessment-orchestrator
```

On Windows, replace `bash run.sh` with `.\run.ps1`. The `--skill` option also
works with `run`, `chat` and `resume`; repeat it for at most three active skills.
No provider-specific plugin or additional account is needed for these local files.
Provider access is still configured separately for the engineering model.

## How the agent uses skills

- `skill_search` returns a bounded set of metadata matches.
- `skill_use` loads the chosen entrypoint and records the package hash in the session.
- `skill_read` reads a named, manifest-listed resource in bounded pages.
- `skill_run` runs a listed Python/Node helper through the normal command gate.

The initial prompt includes up to five metadata suggestions and the selected
entrypoints, not the entire catalog. The agent can choose a relevant skill during
the task and then load only the procedures/templates it needs. Three entrypoints
can remain active within a shared 16,000-character instruction budget; other
technique resources can be inspected as needed. Suggestions are lexical matches,
not a semantic assessment or automatic invocation of every matching skill.

Selections survive resume and follow-up tasks. Session hashes cover the entire
selected package, including references and helper dependencies. A reimport that
changes a selected package requires explicit reselection or a new session.

## Helpers and permissions

For example, inspect the offline reporting helper's usage:

```sh
bash run.sh skills run --workspace /path/to/project security-finding-report scripts/security_reports.py -- --help
```

The command asks for normal process approval. An explicitly supplied `--allow-run`
before the skill name can approve commands for that invocation. Read-only mode
permits discovery, selection and reads, but refuses helper execution. Reading a
script never executes it, and importing the catalog does not run package code.

Python helpers use HYDRA's current environment. The optional JavaScript analysis
helper needs Node.js on `PATH`; its parser and license are bundled under
`security/security-javascript-analysis-review/scripts/vendor/`, with no npm
download required. Helper arguments are passed as argv, without shell expansion.
Helper effects follow ordinary process/verification rules and are not covered
by tracked-file rollback. Approved helpers have normal OS permissions.

Skills do not grant testing scope, add provider access, enable disabled tools,
spawn agents, or satisfy a HackerOne validation check by declaring success.
Reporting helpers create offline drafts. Actual submission still uses the
separate [HackerOne authorization and verifier contract](../HACKERONE.md).
Burp and browser permissions remain effective.

## Catalog maintenance and validation

The manifest is [`security/catalog.json`](security/catalog.json). It records
package metadata and SHA256/size for every resource. Reads reject unlisted paths,
parent traversal, aliases and altered content. These checks detect inconsistent
files; they are not digital signatures or protection against an attacker with
the same OS account. Workspace skill folders are not auto-imported.
Git preserves snapshot bytes across operating systems, including original line
endings, so a Windows import retains valid hashes in a fresh Linux checkout.

To update from the authored source while preserving independent bundled edits:

```sh
python tools/import_security_skills.py --source /path/to/authored/skills --imported-on YYYY-MM-DD
python -m pytest tests/test_engineering_skills.py tests/test_engineering_tui.py -q
```

The importer validates metadata, Python syntax, relative entrypoint links and
credential-like content before writing. It preserves resources, including vendor
licenses, and refuses conflicting destination edits. Snapshot files remain
unchanged unless you explicitly reimport. Retained source references are dated
author guidance; importing them does not reverify every cited external policy.

Tests check every bundled resource hash, real fixture-model skill selection,
reference loading, resume/version changes, traversal/alias refusal, denied and
approved subprocesses, imported offline helper usage, and terminal/CLI discovery.
They establish integration behavior, not vulnerability-detection accuracy or
live model quality across all 300 techniques.
