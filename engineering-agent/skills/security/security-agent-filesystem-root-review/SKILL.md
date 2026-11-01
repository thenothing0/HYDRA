---
name: security-agent-filesystem-root-review
description: "Review agent file-tool root grants, stale handles and revocation generations; ordinary path traversal or POSIX file access belongs in filesystem review."
---

# Agent broker file-root capabilities and grant-generation revocation

Start from: File-tool schema, allowed roots, symlink/parent handling, broker identity and approval scope.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
