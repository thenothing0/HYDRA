---
name: security-prototype-pollution-review
description: "Review JavaScript property merging and prototype trust. Use for reachable prototype pollution and affected consumers, not every unusual object key."
---

# JavaScript prototype pollution

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace external object/path keys through parsing, deep merge, setters and defaults. Identify whether prototype state changes or only an ordinary own property is created.

2. Use an isolated JavaScript fixture and a harmless marker to observe inheritance changes, with cleanup and a valid object control. Never modify a shared live process merely to prove reachability.

3. Follow the polluted value into an actual consumer such as authorization defaults or rendering configuration. Separate a write primitive from an evidenced security consequence and inspect framework/library fixes.

4. Constrain accepted fields and use appropriate prototype-safe containers/merge behavior. Retest inherited versus own properties, permitted nested data and the real downstream consumer.

## Evidence and discrimination

An own property named unusually or a library version match alone does not prove prototype mutation. A pollution primitive does not automatically prove RCE or authorization bypass.

Provide source-to-merge path, inheritance evidence, consumer behavior, local cleanup and the valid nested-object control; label untested gadgets as unverified.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A08:2025 and CWE-1321; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
