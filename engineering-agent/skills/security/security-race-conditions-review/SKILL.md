---
name: security-race-conditions-review
description: "Review concurrent workflows, one-time actions, limit overruns and idempotency. Use for deterministic local races and explicitly authorized bounded state tests."
---

# Concurrency and atomic business invariants

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Write the intended invariant and locate the read/check/reserve/commit boundary across workers, database constraints and queues. Separate sequential replay from a concurrency-only failure.

2. Use deterministic local interleaving or a small approved concurrent fixture. Count authoritative committed effects and identify whether requests share the same operation/principal/context.

3. Review retries, idempotency-key binding, alternate channels and partial failures. Avoid real spending, inventory exhaustion or production stress to amplify impact.

4. Use atomic state transition/uniqueness/transaction semantics suited to the deployment. Verify exactly one intended effect, conflicting-key rejection and successful legitimate parallel work.

## Discrimination and evidence

Two HTTP successes may represent one committed effect. A process lock does not establish cross-worker safety; one failed race attempt is not absence of a flaw.

Record invariant ownership, synchronization method, bounded attempt count, committed ledger/state, operation identity and the actual distributed enforcement boundary.


## Classification and reporting

The initial planning lens is OWASP A06:2025 and CWE-362; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://portswigger.net/web-security/race-conditions) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
