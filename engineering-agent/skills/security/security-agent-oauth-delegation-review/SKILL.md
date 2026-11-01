---
name: security-agent-oauth-delegation-review
description: "Review agent broker connection/account selection and token-exchange actor/resource binding under per-client consent; ordinary OAuth validation is separate."
---

# Agent broker downstream account selection and token-exchange delegation

Start from: User/client grants, token audience/resource, tool routing, tenant/account selection and downstream API call.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
