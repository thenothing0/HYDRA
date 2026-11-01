---
name: security-hsm-key-export-authority-review
description: "Review a supplied HSM export/backup ceremony, quorum, partition and approved recipient; generic PKCS11 wrapping is a separate review and cannot certify hardware policy."
---

# Product-specific HSM export ceremony, quorum and recipient security domain

Start from: Partition roles, exportability/wrap policy, wrapping-key provenance, approvals and client wrapper.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
