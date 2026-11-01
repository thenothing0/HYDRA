---
name: security-tenant-invitations-review
description: "Review organization invitation issuance and acceptance. Use for inviter authority, recipient/tenant/role binding and replay or stale membership grants."
---

# Tenant invitation, recipient and membership-role binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace inviter permissions, intended recipient, organization, proposed role and invitation lifecycle into the durable membership grant. Distinguish a product's provider-specific recipient-bound flow from a deliberately shareable invitation policy.

2. Use two owned tenants/accounts and local test invitation delivery to compare rightful acceptance with one mismatched recipient/tenant/role. Observe actual membership and protected operation authority, not a successful join page or invitation text.

3. Inspect expiry/revocation, repeated acceptance, role changes after issuance, existing users, federated identities and account/email changes. Canonical identity and organization binding must follow the actual provider and product contract rather than display names alone.

4. Bind the issued capability and durable grant to trusted inviter/recipient/tenant/role policy with the required lifetime/consumption rules. Retest valid onboarding, denied mismatches and revoked/stale grants without inviting unrelated people or changing real organizations.

## Decision and evidence

A forwarded URL is not automatically a bypass when sharing is explicitly allowed. An invitation to an organization need not imply a global platform role; establish the precise membership authority and intended recipient contract.

Include provider/product policy, owned inviter/recipient and tenant identities, invitation purpose/fingerprint/lifecycle, final membership/role and protected operation, plus legitimate-onboarding control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://auth0.com/docs/manage-users/organizations/configure-organizations/invite-members) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
