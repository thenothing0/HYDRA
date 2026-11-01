---
name: security-http-403-authorization-review
description: "Investigate an authorized endpoint returning 403 for real access-control bypass. Use for proxy/origin normalization, method and trusted-header disagreements with paired actors and protected-effect verification; no bulk bypass spraying."
---

# 403 assessment: denial → mismatch → protected effect

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. Read [the operational playbook](references/403-playbook.md) for the decision procedure, evidence matrix, false-positive controls and repair acceptance. Use the [runtime contract](references/runtime-contract.md) when host tools are missing. No vendor API or sibling skill is required.

The optional loopback laboratory demonstrates real HTTP responses and state effects in a synthetic edge/origin model; it accepts no remote target.

Keep inventory, suspected behavior, complete source proof and observed runtime effect separate. Establish the actual actor, protected invariant, consumer and entitled control. Preserve missing decisive checks rather than filling report claims from a response code, candidate string or tool output.

Use the [field-specific evidence contract](references/field-guide.md) and [finding template](assets/finding-template.md) to write one report per independent root cause. The [report handoff](references/report-handoff.md) covers current owner/program scope and formatting; preparation does not transmit a report.
