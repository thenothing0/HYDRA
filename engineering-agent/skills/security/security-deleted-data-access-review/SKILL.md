---
name: security-deleted-data-access-review
description: "Review access to user-deleted records across APIs, exports, caches and retained copies. Use for violated deletion/access contracts; does not determine legal retention duties or physical media erasure."
---

# Deletion-state propagation and residual application access

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Establish the owner's actual deletion contract: hide/archive/soft-delete versus access revocation or scheduled purge, permitted recovery/retention and completion timing. Trace the affected record into query APIs, search, exports, signed links and restore jobs as applicable.

2. Use a disposable owned record with a unique synthetic canary and a paired retained control. Perform the authorized deletion, then check only the agreed access paths and identities at the documented completion point, observing returned bytes and state.

3. Inspect caches/indexes, preissued capabilities, background exports and restore behavior without assuming every retained backup must be immediately erased. Separate a denied client response from an accessible alternate copy and an authorized administrator's documented retention access.

4. Enforce the promised access transition across the evidenced paths and prevent unintended re-publication during restore/reprocessing. Retest rightful retained data, denied deleted-record access and declared recovery/retention behavior; leave untested media/backend erasure outside the conclusion.

## Decision and evidence

A soft-deleted record remaining in owner-restricted storage is not automatically exposure or noncompliance. A valid recovery feature can be intentional; demonstrate access that contradicts a supported product/security requirement.

Include deletion/access requirement and timing, synthetic record/state/canary, actor and each tested delivery path, cache/job/capability lifecycle, actual residual access and legitimate retained/recovery control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
