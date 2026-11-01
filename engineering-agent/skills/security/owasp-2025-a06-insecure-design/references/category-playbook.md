# A06:2025 — operating playbook

## Source review

Derive explicit business invariants, authority sources and state transitions from requirements and code. Find the point at which they must become atomic across APIs, queues, webhooks and retries. Decide whether the control is missing by design or incorrectly implemented; propose the remedy at that level.

## Authorized bug bounty / external verification

Use synthetic balances, entitlements or transactions. Agree the invariant, then test skipped/reordered/replayed steps with minimal impact. Only use a small bounded concurrency exercise when its state changes are inside the existing authorization. Prefer deterministic local interleaving when money, inventory or real customers would be affected.

## Minimum evidence for confirmation

A supported intended rule is violated through a reachable workflow with a concrete consequence. Count committed benefits/effects rather than successful HTTP responses. An assumption about discounts or transfer limits is not enough to establish an abuse case.

## Decision branches and limits

A process mutex proves only a process-local property. Distributed services need the actual atomic database/uniqueness/coordination invariant and failure model. Check-and-set, async delivery, duplicate events and operation identity all belong in the verification plan.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
