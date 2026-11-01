# A06:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A06-01 — Supported business rule

- Trace: Requirement/product behavior -> trusted authority -> enforced invariant.
- Controlled verification: Establish the intended rule with owner evidence before probing a synthetic workflow.
- Discriminator: Undocumented assumptions stay questions; ordinary discount behavior may be intended.
- Acceptance: Accepted security invariant is explicit and enforced at the authoritative boundary.

## A06-02 — Ordered workflow transitions

- Trace: Persistent state -> permitted transition -> actor -> side-effect commit.
- Controlled verification: Skip/reorder one controlled step and inspect authoritative state.
- Discriminator: UI navigation is not a state machine; status alone does not show commit outcome.
- Acceptance: Invalid/repeated transitions leave state/effects unchanged; valid paths still complete.

## A06-03 — Atomic one-time benefit

- Trace: Read eligibility -> reservation/uniqueness -> committed benefit -> queue.
- Controlled verification: Use bounded approved attempts or deterministic local interleaving.
- Discriminator: One non-reproducing race attempt is inconclusive; process locks are not distributed guarantees.
- Acceptance: Exactly one committed result under the relevant cross-worker concurrency model.

## A06-04 — Amounts, entitlement and authority

- Trace: Caller assertion -> server-calculated value -> authorization -> commit.
- Controlled verification: Use tiny synthetic amounts/entitlements and independent owner-side readback.
- Discriminator: Legitimate delegated calculation is not automatically untrusted.
- Acceptance: Trusted values are reconciled at commit and cannot be overridden through alternate channels.

## A06-05 — Replay and channel consistency

- Trace: API/webhook/job -> operation identity -> state transition -> deduplication.
- Controlled verification: Replay an agreed one-time fixture through each relevant entry point.
- Discriminator: Replay may be valid for idempotent reads; identify the business contract.
- Acceptance: All channels enforce the same invariant and stable operation identity.

## A06-06 — Resource/abuse constraints by design

- Trace: Actor -> expensive capability -> quota/admission -> durable resource.
- Controlled verification: Review budgets or use bounded local cost instrumentation.
- Discriminator: Do not exhaust live inventory, money or service capacity to prove impact.
- Acceptance: Admission/accounting limits protect intended resources without breaking legitimate usage.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
