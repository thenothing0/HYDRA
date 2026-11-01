---
name: security-finding-report
description: "Normalize and write one evidence-supported vulnerability report per independent finding. Use for splitting assessment results, clear reproduction, impact, attachment isolation and report quality; does not discover a submission destination."
---

# One finding, one report

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Turn the supplied findings into individually reviewable reports. Use [report-contract.md](references/report-contract.md) and [finding-input.json](assets/finding-input.json) for the optional offline tool, or produce the same structure manually. Use [runtime-contract.md](references/runtime-contract.md) when tools are missing.

1. Identify independent root causes and existing finding IDs. Keep one report per issue; attach related issue IDs or shared-root-cause notes. Do not silently combine unrelated issues or create several submissions for the same demonstrated cause without explaining the affected surfaces.
2. Reconcile every title, reproduction step, role, URL, result and impact with supplied evidence. Mark missing prerequisites and unverified escalation explicitly. A source-supported confirmation can be valid without live exploitation, but state that dynamic verification was not performed.
3. Use a concise title describing flaw, affected function and evidenced consequence. Put the actor/setup first, then numbered minimal reproducible actions, expected versus observed behavior, impact, root cause, contextual severity/rationale and remediation. Copy redacted HTTP as text rather than requiring triagers to reconstruct screenshots.
4. Review each report and attachment for secrets/unrelated data, hash the delivered redacted bytes, and keep each report’s attachments separate. Do not attach an unrelated finding’s evidence or private program material to another recipient.
5. Deliver one folder/file per finding plus an index. Keep uncertain cases as drafts with open questions. Report the actual test limits and use the receiving program language/template when available; do not invent translations or claim automated translation occurred.

The optional script creates local drafts only and never sends messages or submits reports. Route discovery and platform formatting can be requested separately; without a verified route, preserve a neutral draft instead of inventing a destination.



For a cross-cutting evidence decision, consult the [family guide](references/decision-playbook.md) only when useful.
