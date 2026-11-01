---
name: security-nextjs-server-actions-review
description: "Review reachable Next.js Server Actions for invocation-time authorization and mutation integrity. Use for action arguments, bound/closed-over state, exported action endpoints and proxy-origin configuration."
---

# Nextjs Server Actions

Check that a callable Server Action enforces the caller, object and operation policy when invoked, even when the rendered UI hides or pre-binds its arguments.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

Exact Next.js/React versions and deployment build, action implementation and references, authentication helper, data-access consumer and an owned two-actor fixture when dynamic verification is appropriate.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the actual missing invocation-time boundary and demonstrated effect. Repair it in the authoritative mutation path, then verify denial, entitled success and absence of partial commits on the repaired build.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.
