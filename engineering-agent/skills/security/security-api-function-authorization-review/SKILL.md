---
name: security-api-function-authorization-review
description: "Review role/capability checks on API functions. Use for BFLA and alternate administrative actions, distinct from another user\u2019s object identifier."
---

# API function-level authorization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map registered operations and required capabilities across methods, versions, admin routes, GraphQL mutations and worker triggers. Establish the actor’s legitimate role and permitted functions.

2. Invoke one controlled administrative/sensitive action using a low-privilege fixture actor, then inspect actual state. Compare an authorized operator control with the same function.

3. Trace shared guards, alternate methods and asynchronous execution that may bypass them. Do not create real admins or perform destructive production actions merely to prove the missing check.

4. Enforce the capability at the authoritative entry and execution boundary. Retest denied/allowed roles and ensure no effect commits before a later error response.

## Evidence and discrimination

An admin-like URL name or a 200 response is not a privileged function proof. BOLA concerns an unauthorized object through an otherwise permitted function.

Include required capability, registered route/handler, role policy, concrete sensitive operation and committed/denied effect with an operator control.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A01:2025 and CWE-862; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
