---
name: security-redis-acl-review
description: "Review Redis ACL users, command categories, key patterns and Pub/Sub scope. Use for cross-tenant command/data authority with version-aware selectors and effective configuration."
---

# Redis command/key/channel authorization and effective ACLs

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map application Redis identities to required command/subcommand, key and channel access. Read effective ACLs including rule accumulation, selectors, categories and runtime version; a pasted configuration fragment may not reflect the currently loaded user.

2. Use an owned disposable Redis instance and synthetic keys/channels to compare a required operation with a forbidden tenant/action tuple. Prefer supported authorization dry-run facilities when available, but distinguish predicted permission from an observed command effect.

3. Inspect multi-key operations, transaction/script consumers, Pub/Sub and persistent-versus-runtime ACL changes applicable to this version. A key prefix convention or numbered logical database alone is not a demonstrated authorization boundary.

4. Constrain the complete effective command/key/channel authority and preserve required clients. Retest permitted operations, denied cross-tenant tuples and relevant selectors/reload behavior without reading real data or invoking administrative/destructive commands for proof.

## Decision and evidence

Redis exposure or a successful authentication does not alone prove cross-tenant data access. A wildcard permission can be intentional for an administrator; establish the actual application role contract.

Include Redis version/runtime ACL snapshot with passwords redacted, principal and required tuple, selector/key/channel matching, synthetic result versus permission prediction and legitimate-client control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
