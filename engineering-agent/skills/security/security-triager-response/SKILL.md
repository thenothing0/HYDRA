---
name: security-triager-response
description: "Draft a concise evidence-grounded response to vulnerability triage questions, severity feedback or duplicate claims. Use for supplied report dialogue; does not send replies, invent private-report evidence or guarantee acceptance."
---

# Evidence-grounded triager clarification and report response

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Use [runtime-contract.md](references/runtime-contract.md) for missing tools and host-independent operation. Read [report-contract.md](references/report-contract.md) for the output/evidence boundary, then use [followup-template.md](assets/followup-template.md).

Use the supplied finding and actual triage message. Identify the platform/program and intended recipient when known. Read the current program instructions relevant to the requested response; do not infer that platform-wide state descriptions override a program's requirements.

1. Extract each concrete question or disputed claim: prerequisites, reproducibility, scope, actual impact, severity or shared root cause. Build a question-to-evidence table and identify the smallest missing artifact; reuse existing evidence when it already answers the question.
2. Reconcile the draft with actual observations. Correct overstated impact or unsupported severity openly. For an authorized new check, preserve the original scope and record its new evidence separately; a triager question does not itself authorize broader testing.
3. Draft a short answer with the setup, decisive steps/result and precise evidence references. Separate confirmed effects, plausible escalation and gaps. If a private duplicate report is inaccessible, describe the known root-cause comparison and ask for an allowed distinction; never invent its contents or claim first discovery.
4. Preserve each finding's recipient and attachment boundary. Follow the actual program language/template, record changed claims and any pending questions, and save one local reply draft per report. Technical validity, program eligibility, duplicate status, severity and reward are distinct decisions.

No automatic follow-up schedule, public disclosure, escalation, comment, status update or submission is created. Sending a reply requires an explicit user instruction. A polite evidence-based challenge can clarify a dispute but does not guarantee acceptance, rewards or a particular platform outcome.

[Review cases](assets/review-cases.json) are authored decision scenarios, not executed evaluations. [Primary platform reference](https://docs.hackerone.com/en/articles/8475030-report-states) — accessed 2026-10-27; it supplies platform context, not a universal workflow for other programs. Recheck the actual program instructions when platform-specific behavior matters.


For a cross-cutting evidence decision, consult the [family guide](references/decision-playbook.md) only when useful.
