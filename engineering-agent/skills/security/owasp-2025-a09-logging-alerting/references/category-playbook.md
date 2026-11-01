# A09:2025 — operating playbook

## Source review

Trace the complete event path: producer, formatter, collector/parser, storage, rule evaluation, test notification sink and response owner. Include failure paths and secret-bearing exception objects. Review event contract, escaping, log access/retention, drop/retry behavior and alert thresholds.

## Authorized bug bounty / external verification

Coordinate a labeled harmless event and a test notification destination. If you have no server/collector visibility, you can assess only externally visible leakage or forging behavior; mark event coverage and alert delivery unverified. Do not infer missing logging from a silent website or page real responders as a test.

## Minimum evidence for confirmation

A required event cannot be reconstructed, sensitive information reaches inappropriate log readers, attacker content forges trusted records, or a required signal fails a documented detection/delivery window. Specify the exact observed stage and access prerequisites.

## Decision branches and limits

Raw multiline logs, parsed events and rendered viewers are different boundaries. An alert rule in source is not evidence of delivery. Production SIEM resilience, retention and response ownership cannot be inferred from the local toy collector.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
