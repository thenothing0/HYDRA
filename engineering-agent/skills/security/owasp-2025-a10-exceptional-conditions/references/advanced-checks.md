# A10:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A10-01 — Unknown security decision

- Trace: Dependency/config -> decision return/error -> authorization fallback -> mutation.
- Controlled verification: Inject timeout/None/error in a local stub and inspect state.
- Discriminator: 503 alone is not proof no mutation occurred.
- Acceptance: Unknown permission never grants the protected capability; legitimate decisions still work.

## A10-02 — Disabled or absent capability

- Trace: Untrusted method/selector -> optional handler/config -> dereference.
- Controlled verification: Exercise an absent feature and a supported-feature control locally.
- Discriminator: A healthy configured branch does not cover absent configuration.
- Acceptance: Unsupported selection rejects safely without panic or insecure fallback.

## A10-03 — Failure around commit

- Trace: State update -> durable commit -> outbound side effect -> response.
- Controlled verification: Inject failure before/after a disposable commit boundary and inspect ledgers.
- Discriminator: Lost response after a successful commit is not rollback.
- Acceptance: Atomicity or documented compensation restores the required business/security invariant.

## A10-04 — Retry identity and conflict

- Trace: Principal/operation/request fingerprint -> idempotency key -> unique result.
- Controlled verification: Repeat the same operation, then attempt conflicting reuse on controlled data.
- Discriminator: Same string key with different actor/body is not the same operation.
- Acceptance: Same request reuses one result; conflicting reuse rejects; workers enforce atomic uniqueness.

## A10-05 — Cleanup and cancellation

- Trace: Resource acquisition -> exception/cancellation -> cleanup -> next request.
- Controlled verification: Use bounded disposable resources and explicit local cancellation/failure.
- Discriminator: Do not demonstrate leakage by exhausting live service resources.
- Acceptance: Resources and transactions reach the intended state and a later valid request succeeds.

## A10-06 — Retry and degradation policy

- Trace: Typed failure -> retry eligibility -> backoff/budget -> secure degraded mode.
- Controlled verification: Use a deterministic stub to count attempts and observe final state.
- Discriminator: Retrying a non-idempotent effect can worsen the incident.
- Acceptance: Attempts are bounded and justified; final behavior preserves the security decision and recovery contract.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
