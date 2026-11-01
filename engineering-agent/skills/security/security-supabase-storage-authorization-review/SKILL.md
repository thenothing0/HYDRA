---
name: security-supabase-storage-authorization-review
description: "Review Supabase Storage bucket/object authority across client roles, RLS policies, signed links and server-side service credentials. Use for Storage operations rather than general PostgreSQL row policy review."
---

# Supabase Storage Authorization

Establish which actor may list, read, create, replace, move, copy or delete a specific storage object and who is allowed to issue access capabilities for it.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

Owned project/buckets, intended public/private model, effective storage.objects policies and helpers, SDK/API versions, server signer code and two owned users/tenants with synthetic objects.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the precise operation, object and actor boundary. Repair bucket/policy/wrapper authority as appropriate, then retest entitled use and denial across source and destination paths. Avoid deleting original objects or changing a live bucket's privacy during discovery.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.
