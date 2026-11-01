---
name: security-cors-review
description: "Assess CORS origin/credential behavior and actual browser-read capability. Use for cross-origin data exposure rather than missing-header checklists."
---

# Cross-origin response access

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map sensitive endpoints, authentication mechanism, origin validation, credential flags, preflight behavior and browser cookie constraints. Establish whether the response is intentionally public.

2. Use a controlled origin and account to test browser-readability of a synthetic sensitive response. Include a permitted-origin control and distinguish request sending from response reading.

3. Review origin parsing, subdomain trust, null-origin cases and alternate ingress paths where applicable. Check actual browser semantics instead of inferring impact from one reflected header.

4. Apply the documented origin policy consistently and minimize cross-origin credential exposure. Retest intended integrations, disallowed reads and relevant preflight responses.

## Discrimination and evidence

Wildcard access to public unauthenticated data is not automatically a vulnerability. Credential/header combinations that a browser rejects do not demonstrate cross-origin disclosure.

Include origin, credential/cookie context, browser-observed response access, protected fixture data and a valid integration control; separate CSRF effects from data reads.


## Classification and reporting

The initial planning lens is OWASP A02:2025 and CWE-942; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://portswigger.net/web-security/cors) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
