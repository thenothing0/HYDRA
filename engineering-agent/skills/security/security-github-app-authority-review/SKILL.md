---
name: security-github-app-authority-review
description: "Review services acting with GitHub App installation tokens. Use for installation/customer binding, repository selection, token narrowing and app-versus-user authority."
---

# GitHub App installation-to-customer and repository authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace an authenticated product customer to the GitHub installation, selected repositories, granted app permissions and requested operation. Distinguish app JWTs, installation tokens and user access tokens; caller-supplied installation IDs are not proof of ownership.

2. Use two owned synthetic installations or a stubbed GitHub API and request an inert repository action. Compare the rightful customer with a mismatched installation/repository and observe the token-request scope and action ledger, without creating commits or comments on unrelated repositories.

3. Inspect installation callbacks, repository-selection changes, suspension/uninstallation and cached token handling under the current provider contract. The provider limits installation authority, but the product must also enforce which customer may invoke that installation.

4. Bind the customer to a verified installation/resource entitlement and request only the required token scope. Retest normal app operations, denied mismatched installations/repositories and relevant membership/installation changes.

## Decision and evidence

An installation ID, app permission listing or provider-valid token alone does not show a customer can use another installation. Prove the product routing/entitlement break and actual supported operation.

Include customer/installation/repository binding, app permission and narrowed token-request evidence, token type, stub-versus-live result, lifecycle assumptions and valid-customer control; redact tokens/private keys.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
