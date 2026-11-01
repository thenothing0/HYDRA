---
name: security-azure-storage-sas-review
description: "Review Azure Storage shared access signatures and the service that issues them. Use for resource/permission scope, recipient authorization, expiry and type-specific revocation."
---

# Azure Storage SAS issuance, capability scope and lifetime

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Identify SAS type, signing authority, target resources/actions and the application issuer's recipient authorization. Separate storage-enforced capability parameters from server-side business rules deciding who may obtain that capability.

2. Use an owned synthetic blob/container and a minimally privileged test SAS. Compare allowed resource/action use with a prohibited request and inspect the issuer binding; never paste full bearer query tokens into report text, logs or external tooling.

3. Review lifetime, protocol/distribution, stored-policy association where supported and the actual revocation mechanism for this SAS type. A service SAS, account SAS and user-delegation SAS do not share every policy/revocation feature.

4. Narrow issuance authority and signed resource/action/lifetime to the stated need, with type-appropriate revocation. Retest intended access, rejected extra resources/actions and the documented expiry/revocation behavior without rotating live account keys for proof.

## Decision and evidence

Possession-based access without a login can be the intended SAS design. A token in a private client flow or a long-looking expiry alone requires context; prove unauthorized issuance, distribution or excess capability against policy.

Record SAS type and redacted parameter semantics/fingerprint, issuer actor/resource policy, synthetic action outcomes, actual capability lifetime/revocation constraints and allowed-use control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
