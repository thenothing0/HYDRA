---
name: security-kafka-acl-review
description: "Review Apache Kafka ACLs and effective broker/controller authorization. Use for principal mapping, topic/group patterns and produce/consume/admin authority across tenants."
---

# Kafka principal, topic/group and transactional authorization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Define the intended principal, operation and topic/group/transactional resource tuple. Record listener authentication and principal mapping, authorizer configuration, ACL patterns, superusers and no-ACL behavior for the deployed Kafka version.

2. Use an owned isolated cluster with synthetic topics/groups or a faithful policy evaluator to compare allowed and forbidden tuples. Bound record counts and retain cleanup; do not enumerate, consume or alter real tenant topics or live consumer offsets.

3. Inspect literal/prefixed/wildcard resources, group authority, internal controller request paths and effective allow/deny behavior. Transport authentication alone does not authorize every operation; a topic grant may not establish the claimed group or transactional capability.

4. Repair the effective principal/resource/operation grants and supported authorizer settings. Retest required producer/consumer behavior, denied cross-tenant operations and relevant controller/listener paths with a minimal synthetic workload.

## Decision and evidence

Seeing broker metadata, a topic name or an authenticated connection is not protected-message access. Confirm the required operation and effective authorizer configuration; do not assume every cluster uses the documented default.

Provide Kafka/version/listener principal mapping, authorizer and matching ACLs, exact resource/operation tuple, synthetic record/offset effect or evaluator limit and valid-client control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://kafka.apache.org/41/security/authorization-and-acls/) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
