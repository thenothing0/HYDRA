---
name: security-background-job-authorization-review
description: "Review authorization across queued tasks, workers and result delivery. Use for caller-selected job authority, delayed entitlement changes and cross-tenant job/status/result access."
---

# Background job actor, tenant and delayed authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace enqueue authorization, message producer trust, actor/tenant/resource identifiers and worker credentials through the job action and result delivery. Define whether the product authorizes at enqueue, execution or both and what revocation/cancellation semantics it promises.

2. Use an in-memory queue or owned local worker with two synthetic tenants and a reversible stub action. Compare a permitted job with a mismatched actor/resource or forbidden result read, observing the worker effect and result owner rather than job ID guessing alone.

3. Review retries, delayed jobs, membership changes, cancellation, scheduled service jobs and result caches. Broker message authenticity/serializer safety does not establish business authorization for the resource named in the task.

4. Bind job identity/inputs to trusted authority and enforce the documented execution/result policy with appropriate idempotency. Retest permitted service/user jobs, denied tenant/resource access, delayed membership scenarios and retry/cancellation behavior.

## Decision and evidence

A predictable job ID or a worker using a service account is not sufficient by itself. A legitimately authorized queued job may complete after a session ends; judge entitlement timing against the actual product contract.

Provide producer/enqueue/worker/result trace, actor and service identity, tenant/resource binding, timing/revocation contract, synthetic queue/effect ledger and valid-job control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://docs.celeryq.dev/en/stable/userguide/security.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
