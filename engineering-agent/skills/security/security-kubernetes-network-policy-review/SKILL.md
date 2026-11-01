---
name: security-kubernetes-network-policy-review
description: "Review Kubernetes NetworkPolicy selectors and effective ingress/egress enforcement. Use for unintended pod/service reachability with the actual CNI and network path."
---

# Kubernetes NetworkPolicy selection and enforced connectivity

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Define the required source/destination/protocol/port tuple and collect all relevant policies, pod/namespace labels and CNI capabilities. Evaluate ingress and egress isolation and additive allows; do not assume policy file ordering creates a deny override.

2. Prefer static selector analysis, then bounded connections between owned synthetic pods/endpoints in an isolated namespace when needed. Compare the permitted and prohibited tuple using real connectivity evidence; a policy manifest alone does not demonstrate dataplane enforcement.

3. Inspect namespace-label edit authority, broad peers, DNS/service translation, host-network/node exceptions and existing-connection behavior applicable to the CNI/version. Keep application-layer authorization separate from network reachability.

4. Constrain the effective tuple and label authority with supported CNI policy features. Retest required traffic and denied paths after rollout, accounting for convergence and service/DNS behavior without scanning unrelated cluster networks.

## Decision and evidence

NetworkPolicy presence, missing namespace policies or a reachable public service is not automatically a tenant-isolation defect. Establish the required boundary, actual endpoint path and plugin enforcement.

Record intended connectivity matrix, rendered policies/labels, cluster/CNI versions, exact source/destination and translated path, bounded connection result, policy timing and required-traffic control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A02:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://kubernetes.io/docs/concepts/services-networking/network-policies/) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
