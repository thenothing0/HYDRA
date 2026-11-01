---
name: security-email-change-review
description: "Review registered-email changes, pending-address confirmation and recovery identity. Use for token/account/purpose binding and premature use of an unverified new address."
---

# Registered-email change and account recovery binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Map current, pending and verified email states to login, notification and recovery consumers. Record reauthentication/confirmation requirements and how a change token binds account, destination, operation and expiry.

2. Use two owned mailboxes with a local mail sink or test delivery. Initiate a legitimate change, then vary one account/address/purpose binding and observe durable identity plus reset delivery. Do not send mail to unrelated recipients.

3. Inspect superseded requests, cancellation, account switching, concurrent pending changes and alternative clients. Determine whether pending or stale addresses acquire recovery authority before the required confirmation and whether an old token can overwrite a newer decision.

4. Keep identity changes pending until the required proofs complete and enforce one-use destination/account/purpose binding. Retest valid change, rejected stale or mismatched confirmation and the resulting login/recovery recipient policy.

## Decision and evidence

A proposed address visible in settings or a notification email is not proof of account takeover. Demonstrate the address becoming an unauthorized identity/recovery destination under the stated proof requirements.

Provide current/pending/final account states, mailbox ownership, confirmation and reauthentication policy, redacted token lifecycle, recovery delivery evidence and normal-change control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A07:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#changing-a-users-registered-email-address) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
