---
name: security-terraform-state-review
description: "Review Terraform state, saved plans and their distribution for unintended sensitive-data access. Use for backend/artifact permissions and sensitive-versus-omitted value lifecycle."
---

# Terraform state/plan confidentiality and artifact recipients

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace sensitive provider/resource values into state, saved plans, outputs, backend versions and CI artifacts. Identify actual readers and retention; distinguish UI redaction via sensitive from omission supported by a specific Terraform/provider feature.

2. Prefer sanitized state/schema and access-policy analysis. If a fixture is needed, use a reviewed local no-cloud configuration and fake marker with an explicitly approved local provider only; initialization/providers and planning can execute code or call services, so do not run an unknown configuration for inspection.

3. Review downloaded state, plan JSON/raw outputs, backups, artifact visibility and backend encryption versus read authorization. Feature support for ephemeral/write-only data is version/provider-specific and does not retroactively remove old snapshots.

4. Restrict artifact/backend access and distribution, minimize retained values using supported features where appropriate and handle historical exposure with the owner. Retest allowed infrastructure operations and denied artifact readers without exercising any recovered credential.

## Decision and evidence

A secret present in owner-restricted state is not automatically a disclosure. A sensitive label does not prove storage omission, and encryption at rest does not deny an authorized backend reader.

Provide Terraform/provider/build and artifact type, synthetic or redacted value context, actual reader/retention policy, state-versus-display evidence and allowed-reader control; never attach raw production state.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A02:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://developer.hashicorp.com/terraform/language/manage-sensitive-data) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
