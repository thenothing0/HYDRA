---
name: security-webauthn-review
description: "Review WebAuthn/passkey relying-party validation and credential-account binding. Use for registration/login ceremonies, challenges, RP/origin policy and user-verification enforcement."
---

# WebAuthn registration and assertion verification

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace ceremony creation and verification through the actual supported WebAuthn library. Record challenge storage/lifetime/session binding, RP ID and origin policy, credential ownership, signature verification and required user-presence/verification semantics.

2. Use owned credentials or a virtual authenticator in an isolated relying party to compare a valid ceremony with one changed binding. Preserve cryptographic validity when testing a binding; a mock response tests application logic only and must not be reported as a full authenticator exploit.

3. Inspect discoverable credentials, account identification, cross-origin/related-origin configuration and registration under an existing session. Review counter/backup handling according to authenticator capabilities; a zero or nonmonotonic counter alone is not universal proof of credential cloning.

4. Enforce the applicable specification/library verification contract and server-authoritative account/ceremony binding. Retest valid registration/login, wrong account/challenge/origin or UV requirement, stale/replayed ceremonies and supported recovery behavior.

## Decision and evidence

No attestation, a syncable passkey or a zero signature counter is not automatically a vulnerability. Identify the actual relying-party requirement and accepted invalid ceremony before claiming an authentication bypass.

Include RP/library/browser/authenticator versions, ceremony type and policy, synthetic credential/account IDs, challenge lifecycle and verified assertion fields, actual logged-in identity and a valid ceremony control; never attach private keys.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A07:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://www.w3.org/TR/webauthn-3/) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
