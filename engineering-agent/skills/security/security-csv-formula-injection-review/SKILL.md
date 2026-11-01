---
name: security-csv-formula-injection-review
description: "Review untrusted data exported to CSV or spreadsheet cells. Use for formula interpretation at the recipient application, including delimiter/quote handling and round-trip behavior."
---

# Spreadsheet formula interpretation of exported fields

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace a lower-trust user field into exported cell boundaries and identify the recipient application, import options, locale and expected text/numeric types. Establish whether another user or privileged reviewer opens the export.

2. Use a tiny owned export and harmless arithmetic marker such as =1+1, with a literal text control. Observe actual cell interpretation in the claimed spreadsheet application; inspecting bytes or running a CSV parser alone does not demonstrate formula evaluation.

3. Review separators, quoting, leading controls and save/reopen behavior relevant to that importer. Keep mere evaluation separate from remote data access or command execution; do not use external-link, DDE, network or command formulas.

4. Preserve untrusted text using the supported typed-cell/export approach or an importer-tested CSV policy appropriate to the product. Retest intended numbers/text, field boundaries and supported round trips; do not promise one universal prefix fixes every spreadsheet.

## Decision and evidence

Formula-looking text in CSV bytes is not sufficient when the recipient imports it as text. A harmless evaluated formula does not prove host compromise or data exfiltration, and program scope may exclude the class.

Include actor/viewer relationship, original field, exact exported cell bytes, importer/version/locale/options, observed formula-versus-literal result, round-trip limits and supported program eligibility.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A05:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://community.owasp.org/attacks/CSV_Injection) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
