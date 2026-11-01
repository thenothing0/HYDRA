---
name: security-archive-extraction-review
description: "Review ZIP/TAR extraction paths, links and expansion limits. Use for archive-specific traversal and worker/storage boundary checks with bounded local fixtures."
---

# Archive extraction and Zip Slip boundaries

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace archive entry names, canonical destination containment, link types, overwrites and permissions through the actual extractor/worker. Establish the intended output root and transaction behavior.

2. Use tiny local archives with an allowed file and a harmless outside-root sentinel. Inspect destinations before writes; do not extract attacker archives on a live host or overwrite unrelated files.

3. Review absolute/platform paths, links, deferred extraction and expanded byte/file-count budgets. Check whether failure leaves partially trusted artifacts or changes later consumers.

4. Enforce bounded entry policy and resolved containment at the write boundary, with cleanup/atomicity appropriate to the application. Retest normal archives, denied escape/link entries and unchanged outside state.

## Evidence and discrimination

An unusual entry name alone is not a successful write escape. A safe-looking string prefix differs from canonical containment; one platform’s path rules may not cover another.

Provide extractor/library context, entry-to-destination trace, bounded fixture contents, before/after output and outside sentinel state, plus documented resource/cleanup limits.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A01:2025 and CWE-22; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://security.snyk.io/research/zip-slip-vulnerability) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.

## Optional local laboratory

Read [lab-scope.md](references/lab-scope.md) before running the [synthetic fixture](scripts/verify_lab.py). Its checks do not replace source/runtime assessment of the actual target.
