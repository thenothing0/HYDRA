---
name: security-package-resolution-review
description: "Review package name/version/source resolution across trusted and untrusted indexes. Use for dependency confusion and install-source drift without publishing packages or running install hooks."
---

# Dependency confusion and package-source selection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map package names, normalization, namespaces, index/mirror settings, lock entries and hashes to the actual package-manager version and install command. Identify the intended publisher/source boundary; different ecosystems have different selection semantics.

2. Prefer static resolution metadata and an offline fixture with inert wheels/manifests or a nonexecuting resolver stub. Compare the intended internal candidate and an untrusted same-name candidate, recording which source is selected; even dry-run tooling may fetch or execute build metadata, so inspect its behavior first.

3. Inspect transitive requirements, fallback mirrors, cache state and lock regeneration paths. A fixed version alone may not bind the publisher/source; distinguish dependency advisory exposure from a reachable package-source substitution.

4. Bind installation to trusted sources/artifacts with the manager's supported configuration and integrity controls. Retest required dependency resolution, rejected untrusted candidates and lock/update workflows without public name claiming, package publication or install-script execution.

## Decision and evidence

A private package name or multiple index URLs alone does not prove a malicious artifact will be chosen. Establish actual resolution inputs/semantics and claimed actor control of the substitute source.

Include manager/version/configuration, normalized name/version/lock/hash inputs, candidate sources and trust, offline/static selection result, build-hook limits and legitimate-resolution control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A03:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://pip.pypa.io/en/stable/cli/pip_install/) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
