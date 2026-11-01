---
name: security-xpath-injection-review
description: "Review untrusted values entering XPath expressions. Use for XML query injection and selector trust; distinguish it from XXE parser resolution."
---

# XPath query injection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace user values and selector structure to the actual XPath evaluator, including namespace/context handling and stored document consumers. Distinguish parsing XML from building a query.

2. Use a small synthetic XML document and local evaluator/instrumentation to compare a literal match with changed selection semantics. Do not query unrelated sensitive nodes on a real target.

3. Inspect variable binding support, dynamic path construction and authentication decisions based on returned nodes. Establish reachability and the intended node/actor boundary.

4. Bind external values where supported and map any structural choices to trusted expressions. Retest legitimate literal values and confirm that prohibited node selection cannot occur.

## Evidence and discrimination

An XML error, XPath syntax reflection or external entity behavior is not XPath injection proof. XXE and query manipulation are separate root causes.

Include evaluator/context, expression versus bound data, synthetic node-selection effect, authority consequence and legitimate query result.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-643; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://owasp.org/www-community/attacks/XPATH_Injection) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
