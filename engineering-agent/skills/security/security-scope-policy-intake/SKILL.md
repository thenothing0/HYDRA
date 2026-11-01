---
name: security-scope-policy-intake
description: "Turn existing authorization and current owner/program policy into actionable assessment boundaries. Use before testing assets or methods when scope/rate/data rules matter; security.txt alone grants no testing permission."
---

# Testing-policy and authorization intake

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Preserve authorization the user already supplied; do not ask again merely because a new skill is loaded. Extract the concrete asset/identity/method/environment and any program terms relevant to the proposed action. A report-destination policy can help discover rules but does not itself grant testing scope.

Record policy URLs or supplied documents, retrieval time/version, asset expressions, explicit exclusions, third-party boundaries, authentication requirements, request/concurrency limits and allowed data handling. Separate unknown from denied. A wildcard hostname match is only one input: ownership, product/environment and vulnerability/method exclusions still apply. A redirect, CNAME, vendor banner or discovered JS URL does not automatically expand permission.

Construct an action ledger: proposed check, affected asset and actor, current evidence of authorization, constraints, expected effect, local alternative and stop condition. Prefer source/local work for unknown live boundaries. Ask only for the specific missing information that blocks a necessary action; continue independent authorized work. Do not invent a generic approval ritual or replace an already clear user instruction.

Before an externally mutating action or disclosure, reconcile the concrete recipient/effect with existing authorization and current policy. Keep private program artifacts with their recipient. If policy and ownership evidence conflict, preserve the draft and identify the exact conflict; do not pick the most permissive interpretation. No submission, live request collection or automated surveillance is performed by this Markdown workflow.

Use [assessment-brief.md](assets/assessment-brief.md), [runtime contract](references/runtime-contract.md) and the [planning catalog](assets/control-catalog.json). [Reference](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html) accessed 2026-10-27 provides analyst context, not a statement that authorization or testing occurred.
