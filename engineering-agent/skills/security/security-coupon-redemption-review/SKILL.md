---
name: security-coupon-redemption-review
description: "Review coupon, referral, loyalty and store-credit redemption rules. Use for repeated benefits, eligibility/stacking and inconsistent debit-credit accounting."
---

# Coupon, credit and benefit redemption limits

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Define the actual benefit invariant: per account/order/campaign limit, eligibility, expiry, stacking and debit/credit conservation. Trace the eligibility check and consumption record to the durable entitlement or balance update.

2. Use synthetic accounts and a nonredeemable fixture benefit to repeat one sequential action and compare an eligible first use. Read persisted benefit/balance state and distinguish idempotent retries from an additional credited benefit.

3. Review cancellation/refund rollback, account/tenant attribution, alternate redemption entry points and atomic check/consume behavior. If simultaneous execution is necessary, switch to a bounded local race fixture and document that distinct prerequisite.

4. Enforce the invariant at durable commitment with appropriate uniqueness/idempotency and compensation. Retest permitted eligibility/stacking, prohibited repeat use and cancellation/retry behavior without creating real balances or rewards.

## Decision and evidence

A second successful HTTP response need not mean a second benefit. Unlimited campaign use or cross-order reuse may be intended; obtain the actual restriction before claiming abuse.

Include campaign/rule provenance, actor/account scope, synthetic benefit identifiers, redemption and ledger before/after state, repeat-versus-retry distinction and eligible-use control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A06:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits/) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
