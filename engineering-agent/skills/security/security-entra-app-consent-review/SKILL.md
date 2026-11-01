---
name: security-entra-app-consent-review
description: "Review Entra application/service-principal grants and resource API enforcement. Use for delegated versus app-only authority, tenant binding and consent-to-operation mismatches."
---

# Microsoft Entra delegated/app-only permissions and tenant binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map the app registration, tenant service principal, granted scopes/app roles and resource API to the intended operation. Distinguish requested permissions, granted consent, issued token claims and the API's actual authorization decision.

2. Use owned test tenants/apps or synthetic claim fixtures at the API gate to compare allowed and wrong-tenant/permission calls. Record whether the token is delegated or app-only; a claim fixture with a stubbed verifier proves only handler logic.

3. Inspect resource audience, issuer/tenant trust and mapping of delegated user authority versus app-only grants. Review who can change credentials/grants and whether installed enterprise-app configuration differs from the developer registration.

4. Enforce the intended token type, tenant/resource and effective operation permission using supported identity libraries and API checks. Retest required delegated/service flows and denied wrong-tenant or insufficient-permission paths.

## Decision and evidence

An admin consent screen, powerful requested scope or valid sign-in alone is not proof of unauthorized resource access. App-only permissions do not represent a signed-in user and must be judged against the service authority contract.

Include tenant/app/service-principal and resource identities, configured versus granted permissions, sanitized relevant claims/token type, actual API gate/result or stub limitation and legitimate-operation control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
