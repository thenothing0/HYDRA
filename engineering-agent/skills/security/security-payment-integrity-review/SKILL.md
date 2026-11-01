---
name: security-payment-integrity-review
description: "Review server authority over order amount, currency, recipient and paid state. Use for price manipulation and mismatched payment-to-order binding in an owned sandbox."
---

# Payment amount, recipient and order-state integrity

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace catalogue/quote authority, cart calculation, currency precision, payment intent, recipient and settlement confirmation to order fulfillment. Identify which values the caller can change and the authoritative server contract for each significant transaction field.

2. Use provider test mode or a local payment stub and synthetic inventory. Change one amount/currency/order binding and compare an ordinary purchase, observing the authoritative ledger and entitlement rather than only the checkout page. Stop before any real charge, refund or shipment.

3. Inspect stale quotes, partial settlement, refunds, duplicate/out-of-order callbacks and state changes after authorization. Verify provider-specific event authenticity separately; a genuine payment event can still refer to the wrong order or amount.

4. Recompute trusted totals and bind authorization/settlement to the intended immutable transaction fields with appropriate currency handling. Retest legitimate pricing, rejected field changes and unchanged inventory/entitlements on failed or duplicate events.

## Decision and evidence

An altered displayed total or accepted request field is insufficient if the server charges and fulfills the authoritative amount. Discounts and partial payments can be valid product features; establish their contract.

Record quote/order/payment test IDs, actor, trusted and submitted values with currency/units, provider-stub boundary, ledger and fulfillment state, expected pricing rule and valid purchase control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A06:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
