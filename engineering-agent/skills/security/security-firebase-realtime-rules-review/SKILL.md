---
name: security-firebase-realtime-rules-review
description: "Review Firebase Realtime Database rules for path grants, write validation and identity/query constraints. Use actual RTDB rules and emulator/client contexts; Firestore rules and Admin SDK access use different boundaries."
---

# Firebase Realtime Rules

Check the effective read/write authority at a Realtime Database path, including inherited grants and atomic updates that change authorization-relevant data.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

Actual RTDB rules, data shape, client auth/custom-claim context, intended path policy and emulator project configuration. Use a synthetic data tree and rules emulator when production writes are outside scope.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the effective grant or missing post-write invariant with the actual client context. Repair the rules and rerun the relevant emulator/owned-path cases, including allowed writes, forbidden cross-user writes and deletion semantics. An emulator result must not be represented as a deployed production exploit.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.
