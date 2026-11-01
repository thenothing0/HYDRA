---
name: security-api-bola-review
description: "Review API object identifiers across owners and tenants. Use for BOLA/IDOR when the endpoint is allowed but a specific object/action is not."
---

# API object-level authorization (BOLA/IDOR)

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map object IDs in paths, headers, bodies, nested references and batch operations to their ownership/tenant policy. Confirm that access to the endpoint itself is permitted for the actor.

2. Use two controlled identities and synthetic private objects. Change only the referenced object and compare returned fields and owner-side state for reads and writes.

3. Inspect indirect object relationships, exported/downloaded records, lists/aggregates and worker paths. Unpredictable UUIDs are identifiers, not authorization enforcement.

4. Enforce object/action policy before disclosing, publishing or mutating protected data and before aggregates/cache reuse. Retest mixed permitted/forbidden batches and the owner control.

## Evidence and discrimination

If the actor must not call the endpoint at all, consider function-level authorization instead. Public/shared objects and status-code differences need policy/state evidence.

Provide actor/action/object matrix, explicit private/shared rule, ID-to-record trace, protected field/state effect and legitimate owner behavior.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A01:2025 and CWE-639; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
