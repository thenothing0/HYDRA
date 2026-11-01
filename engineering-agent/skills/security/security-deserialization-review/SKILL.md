---
name: security-deserialization-review
description: "Review untrusted bytes becoming runtime objects or constructors. Use for unsafe deserialization, nested decoders and type-selection trust; no exploit gadget execution is required."
---

# Unsafe object deserialization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Inventory input formats, serializers, nested wrappers and runtime type resolution. Trace constructors/hooks and subsequent privileged consumers from the actual entry point.

2. Prefer a complete source trace or an inert local constructor marker to establish unsafe object creation. Do not deploy gadget chains, execute OS commands or use live secrets just to demonstrate severity.

3. Review signatures, trusted key origin and schema limits separately. Authenticated data may still be unsafe for object construction, and encoding does not establish integrity or authorization.

4. Use constrained data formats and explicit schemas where appropriate; otherwise enforce a documented type/authority model using supported APIs. Retest valid objects/data, rejected types and absence of pre-rejection effects.

## Evidence and discrimination

A serialized-looking blob or installed library is not a reachable deserialization defect. A signature or denylist alone does not prove that nested object construction is safe.

Record decoder/type/constructor path, reachable actor input, actual inert constructor effect or source proof, trust prerequisites and separately unverified escalation.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A08:2025 and CWE-502; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.

## Optional local laboratory

Read [lab-scope.md](references/lab-scope.md) before running the [synthetic fixture](scripts/verify_lab.py). Its checks do not replace source/runtime assessment of the actual target.
