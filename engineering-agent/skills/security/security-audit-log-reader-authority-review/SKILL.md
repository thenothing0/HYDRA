---
name: security-audit-log-reader-authority-review
description: "Review audit-reader scope carried through query rewriting, partitions, continuation and export projection; generic one-object permissions belong in API reviews."
---

# Audit query scope across partition expansion, cursor and export publication

Start from: Event schema, log-reader roles, tenant/project filters, retention and export endpoints.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
