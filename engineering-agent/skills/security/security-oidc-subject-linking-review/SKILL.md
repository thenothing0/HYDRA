---
name: security-oidc-subject-linking-review
description: "Review OIDC pairwise-subject and sector/client migration mappings; use general OAuth review for ordinary linking and email-based identity assumptions."
---

# Pairwise subject and sector/client migration into existing local accounts

Start from: External identity registry, account-linking rules, email verification policy and existing authenticated linking flow.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
