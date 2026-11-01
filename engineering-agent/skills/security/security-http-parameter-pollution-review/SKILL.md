---
name: security-http-parameter-pollution-review
description: "Review duplicate request parameters and inconsistent value selection across layers. Use for validation/authorization/consumer disagreement, separate from HTTP message framing."
---

# HTTP duplicate-parameter and parser agreement

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map a sensitive parameter through proxy/gateway parsing, validation, signatures, authorization and the final application consumer. Record the actual duplicate/list/type contract and first/last/list/merge behavior per deployed parser version.

2. Use a local replica or owned fixture record with two harmless conflicting values and instrument each layer. Compare a single-value request and observe which value is checked and which drives the protected operation, without broad live probing.

3. Inspect query/body precedence, form/multipart/JSON duplicate keys and reserialization only where supported by the stack. Determine whether an agreed multi-value feature is deliberate or permits a lower-trust value to escape the checked representation.

4. Reject ambiguous sensitive input or normalize once into a trusted representation used by all decision/consumer layers. Retest legitimate arrays/multi-selects, conflicting duplicates and unchanged forbidden resource/state.

## Decision and evidence

Accepting duplicate parameters is not automatically vulnerable. The issue requires an actual validation/authority mismatch or unintended structural interpretation, not a chosen first/last-value convention alone.

Provide raw synthetic request, content type, parser/layer versions, per-layer canonical values, checked-versus-used divergence, protected effect and intended multi-value control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A05:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution/) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
