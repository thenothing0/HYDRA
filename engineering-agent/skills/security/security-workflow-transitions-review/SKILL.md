---
name: security-workflow-transitions-review
description: "Review server-enforced state transitions and prerequisites in approval/workflow systems. Use for skipped steps, stale approvals, reordering and invalid terminal-state actions."
---

# Protected workflow transitions and business prerequisites

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Derive the workflow state graph from requirements and authoritative state, recording who may trigger each transition and which prerequisites must hold. Keep interface navigation separate from the server transition/side-effect boundary.

2. Use an owned synthetic record to attempt one skipped or out-of-order transition and compare the normal sequence. Observe persistent state and downstream effects, not merely a reachable page or a success response.

3. Review changed data after approval, stale transition requests, cancellation/reopen paths and compensation after a failed step. Determine whether a previously authorized decision still applies to the exact record version being committed.

4. Enforce transition, actor and version/prerequisite checks atomically at commitment. Retest the prohibited sequence, the full valid workflow, stale requests and required recovery without orphaned side effects.

## Decision and evidence

A visible final screen or an intentionally optional step does not prove a bypass. A prohibited transition requires an evidenced business/security prerequisite and an actual state or authority violation.

Record the required graph/rule, actor, source and target states, record version, minimal transition sequence, durable side effects and a valid complete-workflow control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A06:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows/) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
