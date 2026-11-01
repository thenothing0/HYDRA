# A04:2025 — operating playbook

## Source review

Map sensitive fields and keys through transit, storage, backup, export and deletion. Review high-level crypto calls, trust/hostname verification, secure randomness source, nonce requirements, password format/work-factor configuration and migration. Establish security purpose before classifying hash usage.

## Authorized bug bounty / external verification

Use synthetic credentials and data to inspect exposed transport/certificate behavior or client crypto formats within scope. Treat encryption-at-rest, key custody and server password hashing as unavailable unless supported by code/configuration or owner evidence. Do not submit discovered secrets to external services.

## Minimum evidence for confirmation

A required confidentiality/authenticity/identity property fails, or source evidence establishes weak security-relevant cryptography or key lifecycle. Preserve the exact library/build, key purpose and attacker capability. Tiny output samples cannot establish cryptographic entropy.

## Decision branches and limits

A successful TLS edge handshake says nothing about hidden service links. A repaired generator may leave existing keys compromised. A password record prefix does not prove safe parameters. Any numerical algorithm/work-factor recommendation must come from current applicable primary guidance, with a migration plan.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
