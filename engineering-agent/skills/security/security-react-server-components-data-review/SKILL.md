---
name: security-react-server-components-data-review
description: "Review React Server Component data passed to browsers through props, Flight/streamed payloads and rendered output. Use for hidden-field disclosure and request/cache context mistakes; not merely for an RSC response format."
---

# React Server Components Data

Determine exactly which server-derived values reach an unauthorized browser, including values the UI never displays.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

Exact React/framework versions, server-to-client component boundary, data-access code and serializer/DTO, plus attributable HTML/RSC responses from owned actors or a synthetic local application.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the exact protected values/fields delivered to the actor, with redacted wire evidence. Repair the server data-access/projection/cache boundary and retest both confidentiality and legitimate rendering.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.
