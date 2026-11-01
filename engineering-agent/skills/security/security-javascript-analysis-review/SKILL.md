---
name: security-javascript-analysis-review
description: "Analyze supplied JavaScript bundles, source maps and source-to-consumer flows. Use for endpoint reconstruction, client trust, browser/Node sinks and evidence-backed findings; endpoint strings are inventory, not vulnerabilities."
---

# JavaScript analysis: artifact → data flow → supported finding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. Read [the operational playbook](references/javascript-playbook.md) for the decision procedure, evidence matrix, false-positive controls and repair acceptance. Use the [runtime contract](references/runtime-contract.md) when host tools are missing. No vendor API or sibling skill is required.

Optional AST and source-map tools are offline and never execute input code; see the playbook for Node/Python requirements and analysis gaps.

Keep inventory, suspected behavior, complete source proof and observed runtime effect separate. Establish the actual actor, protected invariant, consumer and entitled control. Preserve missing decisive checks rather than filling report claims from a response code, candidate string or tool output.

Use the [field-specific evidence contract](references/field-guide.md) and [finding template](assets/finding-template.md) to write one report per independent root cause. The [report handoff](references/report-handoff.md) covers current owner/program scope and formatting; preparation does not transmit a report.
