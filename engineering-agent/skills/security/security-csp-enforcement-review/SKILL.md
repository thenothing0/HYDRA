---
name: security-csp-enforcement-review
description: "Review Effective Content Security Policy enforcement across headers, HTML policies and frame contexts."
---

# Effective Content Security Policy enforcement across headers, HTML policies and frame contexts

Start from: All response CSP headers, meta policies, script insertion callsite, browser console/violation records and legitimate script bootstrap.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
