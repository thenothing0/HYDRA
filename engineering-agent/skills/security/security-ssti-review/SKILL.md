---
name: security-ssti-review
description: "Review untrusted template source and server-side expression evaluation. Use for SSTI; distinguish ordinary template parameters and client-side rendering."
---

# Server-side template injection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace which bytes become template source versus data parameters, and identify the renderer, language context, privileges and available objects from source/configuration.

2. Compare a literal text control with an inert arithmetic/string sentinel in a local or scoped fixture. Confirm evaluation occurs on the server rather than in browser JavaScript or a separately intended expression feature.

3. Inspect stored/preview/email/background rendering and alternate engines. A single delimiter match does not identify an engine; avoid object traversal, file reads or command execution merely to embellish a report.

4. Keep user content as data where possible. If authoring templates is intended, document the trusted actor and isolation contract, then test the actual permitted template feature and rejected authority boundary.

## Discrimination and evidence

An exception, reflected delimiter or deliberately authorized template editor alone is not an unauthorized SSTI claim. Do not label benign evaluation as full RCE without supporting evidence.

Record source-versus-data flow, server evaluation evidence, renderer/context prerequisites, legitimate rendering control and explicitly unverified escalation.


## Classification and reporting

The initial planning lens is OWASP A05:2025 and CWE-1336; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://portswigger.net/web-security/server-side-template-injection) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
