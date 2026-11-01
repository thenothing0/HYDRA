---
name: security-gcp-iam-review
description: "Review Google Cloud principal/permission/resource authorization. Use for inherited allow/deny policies, principal boundaries, conditions and reachable service-account delegation."
---

# Google Cloud effective IAM and inherited resource authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Define the intended principal/permission/resource/context tuple and resource ancestry. Collect applicable allow, deny and principal-boundary policies, conditions, group/service identities and service-specific access controls; unavailable layers remain explicit gaps.

2. Evaluate the tuple using current provider semantics and authorized read-only troubleshooting tools where available. Distinguish an evaluator result from a harmless synthetic resource operation; do not infer every service supports every policy type or diagnostic capability.

3. Trace inherited grants and any reachable service-account impersonation/delegation against all required permissions and organization controls. A role name or isolated binding is not a complete effective-access or privilege-escalation proof.

4. Repair the evidenced grant, condition, delegation or boundary at the right hierarchy level. Retest required service behavior and denied tuples with the same principal/resource context, recording remaining policy visibility limits.

## Decision and evidence

A broad project role or resource policy fragment alone does not establish usable unintended access. Document the intended administrative authority and all applicable restrictions before confirming a violation.

Provide sanitized principal form, permission/resource/context, hierarchy and policy snapshots, condition inputs, evaluation-versus-operation evidence, missing layers and an authorized-use control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://docs.cloud.google.com/iam/docs/policy-types) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
