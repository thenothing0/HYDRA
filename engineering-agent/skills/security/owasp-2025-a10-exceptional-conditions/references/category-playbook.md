# A10:2025 — operating playbook

## Source review

Map authorization, state changes and resource ownership to every fail point, including None/unknown decisions, timeouts, cancellation, partial commit and late responses. Inspect typed error propagation, secure fallback, transaction/outbox boundaries, idempotency identity and bounded retry behavior.

## Authorized bug bounty / external verification

Start with inert malformed input in a controlled account. For outages/partial commits use local dependency stubs unless live fault injection is explicitly in scope. Observe persisted and queued state before/after the error, then retry the same operation identity and verify recovery when dependencies return.

## Minimum evidence for confirmation

The abnormal condition causes an insecure decision, persistent inconsistency, duplicated effect, sensitive leakage or evidenced material availability impact. An isolated error code or exception text alone is not sufficient.

## Decision branches and limits

Bind idempotency keys to principal, operation and normalized request fingerprint; reject conflicting reuse, and enforce uniqueness atomically across workers. A connection loss after commit is not the same as a rollback. Avoid generic retries of non-idempotent actions or swallowing exceptions without a defined state.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
