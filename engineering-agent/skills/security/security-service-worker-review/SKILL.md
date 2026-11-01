---
name: security-service-worker-review
description: "Review service-worker registration, controlled clients and private CacheStorage reuse. Use for untrusted worker authority or cross-account responses across logout/update/offline states."
---

# Service worker scope, lifecycle and private response storage

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map who controls worker script bytes/imports, registration URL/scope and controlled clients. Trace fetch/message handlers and cached private responses to the account/session contract, separating service-worker storage from shared HTTP caches.

2. Use an owned local origin and disposable browser profile with two synthetic accounts. Compare a rightful fetch with account switch/logout/offline use and observe the active controller, cache entry and delivered canary; clear fixture registrations/storage afterward.

3. Inspect install/wait/activate transitions, old controlled tabs, cache naming, message peers and update paths. A path scope is not an origin-level security boundary, and a new worker registration does not prove existing clients use it.

4. Protect worker script/control authority and enforce the intended private response lifecycle and message contract. Retest valid offline functionality, account changes, old/new controlled clients and cleanup without deleting unrelated browser data.

## Decision and evidence

Registration, a broad scope or intended offline storage alone is not a vulnerability. Establish the forbidden actor/data/control transition under the product policy; distinguish worker cache responses from browser history or a server cache.

Record origin/profile/browser/build, registration and actual controller lifecycle, account/canary identity, cache/fetch trace, observed delivery after state change and legitimate offline control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://www.w3.org/TR/service-workers/) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
