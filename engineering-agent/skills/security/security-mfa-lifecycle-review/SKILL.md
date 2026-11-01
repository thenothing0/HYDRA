---
name: security-mfa-lifecycle-review
description: "Review MFA activation, factor replacement, backup codes and alternate login/recovery paths. Use for incomplete MFA sessions, factor binding and unintended assurance downgrade."
---

# MFA enrollment, replacement, recovery and downgrade

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map pre-factor versus fully authenticated sessions and the account-bound enrollment, replacement, disabling and recovery states. Record the product assurance/recovery policy and what proof is required before each sensitive factor change.

2. Use owned test accounts with synthetic factors to compare an incomplete login/recovery session against a completed session at one protected operation. For factor changes, observe durable enrollment and subsequent login authority; avoid sending unsolicited SMS/push messages.

3. Inspect backup-code consumption, alternate clients, remembered-device policy, partial enrollment and factor rollback. Distinguish an expressly allowed recovery method from a route that silently grants higher assurance than it established.

4. Bind factor actions to the correct account and required proof, enforce the server session state and consume one-use recovery material appropriately. Retest legitimate recovery, denied incomplete sessions, replaced factors and replay behavior under the policy.

## Decision and evidence

Absence of MFA on a product that does not promise it, or an intentional recovery option, is not automatically a bypass. A recovery code may replace a lost factor by design; assess binding, consumption and assurance.

Provide the assurance/recovery contract, actor/account/session state, factor operation, redacted token purpose, durable factor/session result and valid login/recovery control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A07:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
