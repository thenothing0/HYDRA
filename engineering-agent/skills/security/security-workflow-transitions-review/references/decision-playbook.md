# Business invariant, durable state and atomic commitment

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Write the product invariant explicitly: amount/currency/recipient, eligibility/use count, permitted state transition, required approval, concurrency invariant or enqueue/execution authority timing. Derive it from owner evidence rather than imagining a limit.

Use synthetic records/benefits, provider test mode and inert worker effects. Observe durable ledger/state and downstream entitlement, not a response flag. Compare the allowed sequence and measure exactly what a retry, cancellation or concurrent action commits.

Optional workflow steps, intended partial payments, idempotent retries and authorized delayed jobs are not automatically abuse. A 200 can correspond to no new benefit; an error can follow a committed change. Separate sequential logic failure from a deterministic concurrent race and bound any concurrency experiment.

Repair the check/commit/compensation boundary while preserving valid business behavior. Retest the original invalid sequence, normal purchase/approval/worker flow and cleanup/rollback. Do not perform real charges, credits, shipments or production load merely to illustrate impact.

## Evidence before conclusion

- owner-supported invariant and actors
- record/quote/version/state and commit boundary
- minimal sequence or deterministic concurrency schedule
- durable before/after ledger/entitlement and failure timing
- normal, retry/rollback and prohibited-sequence controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
