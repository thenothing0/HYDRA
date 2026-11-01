---
name: security-firestore-rules-review
description: "Review Cloud Firestore Security Rules for document/query access and caller-writable authority fields. Use client-rule paths and distinguish server SDK/IAM authorization."
---

# Cloud Firestore rules, caller identity and document mutations

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Record the deployed rules/version, client access path, document schema and authenticated claims. Trace get/list/create/update/delete conditions and existing versus proposed document data to the intended user/tenant ownership and immutable fields.

2. Use the Firestore emulator or an owned test project with two synthetic identities and documents. Compare permitted and forbidden reads/writes, including owner/tenant-field changes; observe accepted persisted state, not just a rules snippet.

3. Inspect overlapping/nested matches, query constraints, custom-claim lifecycle and batch/transaction-dependent checks where used. Rules are not query-result filters. Server client libraries use a different authorization path; their access is not evidence that client rules were bypassed.

4. Enforce trusted ownership and allowed document transitions in the relevant rule paths and protect server-side IAM/API access separately. Retest valid queries/mutations, denied cross-tenant operations and immutable-field changes against the actual deployed/emulated rules.

## Decision and evidence

A Firebase project ID/client key, console access or server SDK read alone is not a Security Rules vulnerability. Establish the actual lower-trust client path and protected document/query action.

Provide rules/build/project-or-emulator identity, client versus server path, actor claims, document before/after fields, query/action, actual rules result and permitted-client control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://firebase.google.com/docs/firestore/security/rules-conditions) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
