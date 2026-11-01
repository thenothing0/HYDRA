---
name: security-xxe-review
description: "Assess XML entity/DTD resolution and parser configuration in authorized applications. Use for XXE across XML imports, document processing and alternate parser entry points."
---

# XML external entities and parser capabilities

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Locate each XML parser construction and downstream resolver, including document conversion, uploads and queued imports. Identify library/build and actual feature settings rather than assuming defaults.

2. Use an inert local entity or owned resolver stub to observe prohibited external resolution. Record whether bytes were resolved, parsed, returned or only caused an error; keep these consequences separate.

3. Check wrappers that create new parser instances and paths that bypass central configuration. Inspect expansion/resource controls in source or bounded local fixtures; do not trigger expansion exhaustion on live services.

4. Disable unnecessary external resolution and unsafe DTD behavior with the specific supported parser API. Verify legitimate XML still processes and rejected references cause no outbound fetch or sensitive content use.

## Discrimination and evidence

XML acceptance or a parser error is insufficient. A blocked direct endpoint does not establish safe behavior in a converter or background parser.

Provide parser initialization, resolver event/source trace, controlled document, feature/context prerequisites and legitimate-document control.


## Classification and reporting

The initial planning lens is OWASP A02:2025 and CWE-611; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
