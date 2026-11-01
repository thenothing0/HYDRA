---
name: security-sql-injection-review
description: "Review SQL values, identifiers and raw ORM/stored-procedure paths. Use for SQL injection confirmation and repair with local or controlled database fixtures."
---

# SQL injection and structural query control

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace untrusted values and structural selectors through query builders, raw ORM calls, dynamic stored procedures and the actual database API. Record parameter binding separately from identifier/operator selection.

2. Use a disposable database and synthetic rows to compare a literal value with a bounded syntax-changing sentinel. Instrument the query/returned fixture set when possible; avoid production data dumps and long delay probes.

3. Follow stored input into exports, reporting jobs and second-order queries. Review database privileges and whether an alleged vulnerable function is reachable from an authorized entry point.

4. Bind values and map structural choices to trusted constants using supported APIs. Retest punctuation, Unicode, valid sorting, denied structural choices and the original failing row-selection behavior.

## Evidence and discrimination

A database error or an old dependency alone does not prove SQL control. ORM usage does not guarantee that raw expressions and structural arguments are safe.

Provide source-to-query trace, binding/structure evidence, exact synthetic row effect, database/feature prerequisites and minimal reproduction without unrelated data.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-89; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
