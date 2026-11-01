---
name: security-csrf-review
description: "Assess cross-site authenticated state changes and CSRF defense binding. Use for cookie/session-based action forgery and alternate state-changing paths."
---

# Cross-site request forgery

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Identify sensitive state changes, ambient credentials, token/origin checks, cookie policy and method/content-type alternatives. Trace server action before and after any guard.

2. Use a controlled account, disposable state and owned browser origin. Demonstrate the state change from the cross-site context and verify it independently, not just a successful response.

3. Check whether tokens bind to session/action as required and whether alternate routes/methods omit the guard. Do not send requests from or affect other users.

4. Repair the shared server-side defense appropriate to the actual authentication/browser model. Verify normal form/API behavior, denied foreign requests and absence of committed side effects.

## Discrimination and evidence

A missing token is not proof when other effective defenses apply. Bearer-only APIs without ambient credentials have a different attack model; CORS read denial alone does not prevent all state changes.

Provide ambient-auth prerequisites, browser origin/request context, target action, fixture state before/after, defense behavior and legitimate-action control.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-352; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
