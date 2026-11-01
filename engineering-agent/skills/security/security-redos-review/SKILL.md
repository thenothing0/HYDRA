---
name: security-redos-review
description: "Review attacker-influenced regex patterns/subjects and matching cost. Use for reachable ReDoS with source analysis and strictly bounded isolated measurements."
---

# Regular-expression matching cost and bounded input control

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace caller-controlled pattern/subject lengths, the actual regex engine/flags/API, repetition/ambiguity and the request/worker execution budget. Determine whether input limits apply before matching and whether a failing or successful match is the expensive case.

2. Prefer source analysis first. If measurement is useful, use tiny increasing fixture sizes in a disposable child process with hard wall-time/size caps and one attempt at a time; terminate on the first cap and never send expensive probes to a live service.

3. Separate compile cost, catastrophic backtracking, global-search repetition and ordinary linear work. Record engine version, lengths, timing method and uncertainty; a static warning or one noisy timing sample is not a production outage demonstration.

4. Choose an equivalent bounded/linear-time strategy or supported engine limits appropriate to required semantics, with admission limits before work. Retest accepted/rejected input language, bounded failure behavior and valid feature performance inside the local budget.

## Decision and evidence

Nested quantifiers or a slow local sample alone do not establish exploitable service exhaustion. Confirm reachability, effective input budgets and actual engine behavior; a generic timeout in a thread may not stop underlying work.

Include pattern provenance and redacted pattern, engine/version/flags/API, controlled lengths and hard caps, local timing/termination results, worker reachability and legitimate language-equivalence controls.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A06:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://community.owasp.org/attacks/Regular_expression_Denial_of_Service_-_ReDoS) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
