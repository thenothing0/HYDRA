---
name: security-electron-ipc-review
description: "Review Electron preload/context bridges and main-process IPC authority. Use for untrusted renderer/frame messages reaching protected native operations."
---

# Electron renderer-to-main IPC and native capabilities

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace renderer content/navigation, BrowserWindow preferences, preload exports and IPC handlers to native effects. Record actual Electron/build configuration and which renderer/frame can invoke each capability; context isolation alone does not authorize a broad bridge.

2. Use an owned local fixture build and a stub native ledger. Compare an intended renderer with a lower-trust frame/message, observing trusted sender context, validated parameters and committed stub effects without reading real host files or executing commands.

3. Inspect child windows, navigation changes, custom protocols, external URL dispatch and handler responses. Determine whether frame origin/identity and action/resource authority remain valid at use; do not trust a message field that merely claims a trusted URL.

4. Expose narrow validated operations and enforce caller/action/resource checks in the privileged process with appropriate isolation. Retest the intended desktop workflow, denied renderer/frame and changed-navigation cases on the release-equivalent build.

## Decision and evidence

A permissive preference or an IPC channel name alone is not a reachable native compromise. Establish lower-trust content control and the exact protected operation; an inert bridge invocation is not arbitrary code execution.

Include build/runtime and window/preload configuration, content/frame ownership, bridge-to-handler trace, trusted sender evidence, exact synthetic parameters, stub effect and intended-renderer control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://www.electronjs.org/docs/latest/tutorial/security) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
