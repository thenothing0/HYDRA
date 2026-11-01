---
name: security-nosql-injection-review
description: "Review NoSQL selector/operator construction, input types and query trust boundaries. Use for operator injection or query-language misuse, not generic database exposure."
---

# NoSQL operator and query injection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map external JSON/form types through schema coercion, object merging and selector construction to the actual driver query. Separate accepted literal data from caller-chosen query operators or executable expressions.

2. Use synthetic documents and instrumented/local queries to compare scalar, unexpected object and valid structured input. Establish the changed result or authority, not just a parser error.

3. Inspect login filters, search options, aggregation construction and stored values used by later jobs. Review allowlisted operators/fields and whether framework coercion changes the intended type boundary.

4. Build queries from constrained schema values and trusted structural choices. Retest valid structured features, operator-like text as data and rejection of unexpected types without changing protected documents.

## Evidence and discrimination

Accepting JSON objects is not automatically injection when the product deliberately supports a constrained query schema. A rejected malformed selector is not bypass evidence.

Record input type/operator control, schema/driver path, intended query contract, synthetic query-result effect and whether identity or object authorization was actually crossed.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-943; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
