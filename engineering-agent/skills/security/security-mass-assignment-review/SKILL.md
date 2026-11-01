---
name: security-mass-assignment-review
description: "Review caller-writable object fields and model binding. Use for mass assignment/property-level authority, separate from object and endpoint authorization."
---

# API object-property authorization and binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map schema/DTO/model binding and every caller-controlled property to persistent server state. Derive writable fields per role and distinguish server-managed identity, tenant, price and privilege values.

2. Use a controlled record to submit one harmless forbidden property and read authoritative state back. Compare the permitted editable field; parsing or a successful response alone is insufficient.

3. Inspect nested objects, bulk updates, alternate content types and create-versus-update paths. Follow validators/serializers that may expose fields even when writes are protected.

4. Apply explicit role-appropriate field mapping and enforce server authority at persistence. Retest allowed edits, forbidden/nested attributes and unchanged protected state.

## Evidence and discrimination

Ignored extra JSON fields are not successful mass assignment. A property visible to its rightful owner may be intended; object access and field authority are separate dimensions.

Include role/field policy, binding path, submitted property, persisted before/after state and permitted-field control. Group routes sharing the same root cause explicitly.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A08:2025 and CWE-915; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
