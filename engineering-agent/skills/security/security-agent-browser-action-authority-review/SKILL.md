---
name: security-agent-browser-action-authority-review
description: "Review stale DOM/form targets, frame origin, navigation and account changes between agent preparation and commit using an owned simulator."
---

# Agent prepared browser actions bound to current frame, form and account

Start from: User-authorized task, current origin/account, page/tool content, action parameters and submission boundary.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
