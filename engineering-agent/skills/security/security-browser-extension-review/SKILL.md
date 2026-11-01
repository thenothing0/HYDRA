---
name: security-browser-extension-review
description: "Review browser-extension content/page messages reaching privileged background or native capabilities. Use for sender validation, action/resource authority and permission-context confusion."
---

# Browser-extension messages and privileged capability gates

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map manifest permissions/host grants, content scripts, page bridges, external messaging and background/service-worker handlers. Trace trusted runtime sender metadata separately from message fields claiming origin, tab or account identity.

2. Use an owned unpacked fixture extension in a disposable profile and a controlled page. Compare a permitted sender with a lower-trust request to a stub capability, observing the actual extension gate and result without reading real browsing data.

3. Inspect message schema, URL/resource selectors, cross-extension callers, native messaging handoff and lifecycle state. Restrict the operation requested by a less-trusted content script even if the extension itself holds broad browser permissions.

4. Enforce sender and per-action/resource authorization at the privileged handler and reduce unnecessary grants. Retest intended integrations, rejected forged payload identity and prohibited capabilities across relevant worker restarts.

## Decision and evidence

Broad permissions, an externally connectable page or a content-script message alone is not a vulnerability. Prove a lower-trust actor can invoke a protected operation outside the extension's intended contract.

Record manifest/build/browser/profile context, sender metadata and controllable payload, message-to-capability trace, permission state, inert observed action and valid-sender control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://developer.chrome.com/docs/extensions/develop/concepts/messaging) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
