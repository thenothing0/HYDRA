---
name: security-email-header-injection-review
description: "Review caller-controlled email headers and envelope recipients. Use for header injection, malformed address handling and unintended mail routing through application mail builders."
---

# Email header structure and envelope-recipient authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace form/profile values through structured address/header APIs, serialization and the SMTP envelope. Distinguish display names, header recipients and actual envelope recipients; identify any concatenation into raw header or SMTP command text.

2. Use an in-memory serializer and local sink with synthetic addresses only. Compare an ordinary value with a newline/delimiter-bearing value and inspect parsed headers plus envelope recipients. Do not infer delivery from message text or send email to external addresses.

3. Inspect encoding/folding, alternate mail providers, template-generated headers and parser/version differences. Determine whether validation rejects the input before queueing, preserves it as literal body data or creates a new structural field or recipient.

4. Use supported structured mail/address APIs with appropriate field validation and explicit envelope authority. Retest legitimate Unicode/display names, prohibited structural input and unchanged recipient lists after serialization and queue handoff.

## Decision and evidence

A newline in message body, a legitimate folded header or a suspicious-looking address is not header injection. Actual envelope-recipient expansion and merely adding a visible header are different effects.

Record input field/context, mail library/provider version, builder/serializer trace, parsed synthetic header structure, actual envelope list, rejection stage and valid-name control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A05:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://docs.python.org/3/library/email.policy.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
