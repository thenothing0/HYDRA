---
name: security-passwordless-magic-link-review
description: "Review email magic-link login for account/purpose binding, one-time consumption and session creation. Use owned mailboxes or local fixtures; distinguish passwordless sign-in from password-reset flows."
---

# Passwordless Magic Link

Establish that consuming a login capability authenticates only its intended account, purpose and transaction under the application's declared cross-device policy.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

Issuer/consumer code, token storage/expiry semantics, email template and redirect settings, declared cross-device behavior, mail-preview behavior and controlled mailboxes/accounts. Source/local review remains possible without a mailbox.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the exact account/purpose/session boundary crossed, supported token lifecycle and observed effect. Retest the legitimate same-device/cross-device path allowed by policy, replay rejection and session invalidation after repair.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.
