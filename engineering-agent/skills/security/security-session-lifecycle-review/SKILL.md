---
name: security-session-lifecycle-review
description: "Review session rotation, binding, refresh and revocation against declared policy. Use for fixation/lifecycle issues, not JWT algorithm validation."
---

# Session fixation and lifecycle controls

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map anonymous-to-authenticated transitions, privilege changes, cookie/token issuance, refresh, inactivity, logout and recovery. Identify server authority and the intended revocation model.

2. Use controlled sessions to compare authority before/after login or role change, then test old identifiers according to policy. Preserve only redacted identifiers or local correlation labels.

3. Inspect alternate login paths, concurrent sessions, refresh replay, cookie scope and browser storage. Distinguish immediate invalidation from documented bounded stateless token lifetime.

4. Repair central session handling and test legitimate refresh/re-login along with rejected fixation or overlong authority. Verify both identity and action permissions after transitions.

## Evidence and discrimination

A changed cookie alone is not proof of safe authority rotation, and a readable token is not a session vulnerability. Policy and protected-path behavior determine the finding.

Record lifecycle event, pre/post authority, policy times/build, controlled protected operation, invalidated or retained sessions and actual security consequence.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A07:2025 and CWE-384; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
