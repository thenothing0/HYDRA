---
name: security-document-processing-review
description: "Review image/document conversion workers, effective parser policy and execution isolation. Use for unintended delegates, file/network access, resource budgets and output publication."
---

# Untrusted image/document worker capabilities and isolation

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map the accepted input to the actual decoder, delegate/converter, temporary files and published output. Record runtime versions/effective policy, worker identity, filesystem/network authority and required formats rather than relying on filename extension.

2. Use tiny inert local fixtures and stub delegates/access monitors to observe the permitted and prohibited capability. Inspect effective configuration first; no exploit documents, decompression bombs, real host files or external network callbacks are needed.

3. Review format sniffing, embedded references, alternate decoders, temp-file ownership/cleanup, resource admission and post-processing. Separate upload admission from the worker capability actually invoked; a sandbox declaration is not proof of its effective restrictions.

4. Constrain required decoders/delegates and worker file/network/compute authority using supported runtime policy and isolation. Retest intended conversion, rejected capability, bounded failure cleanup and safe publication under the deployed version.

## Decision and evidence

A converter dependency, enabled format or untrusted upload alone does not prove code execution or file disclosure. Establish the reachable parser/worker authority and actual forbidden capability or a complete source-supported boundary failure.

Provide pipeline/format trace, effective runtime policy/version, worker authority and isolation, inert monitored capability result, temporary/output lifecycle and valid-format control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A02:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://imagemagick.org/security-policy/) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
