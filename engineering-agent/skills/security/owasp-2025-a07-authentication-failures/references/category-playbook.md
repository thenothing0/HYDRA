# A07:2025 — operating playbook

## Source review

Map each identity transition: registration, login, reset, recovery, MFA changes, refresh, logout and federation. Trace account linking, validated claims, trusted keys, token purpose/audience/issuer/expiry, session rotation and documented revocation. Check alternate branches, not just the primary form.

## Authorized bug bounty / external verification

Use controlled accounts, inbox sinks and sessions. Show the identity before and after each recovery action and whether MFA still applies. A successful reset request is not proof of takeover. Evaluate abuse controls from configuration or a small budget of test attempts; never spray passwords or enumerate unrelated accounts.

## Minimum evidence for confirmation

A caller gains identity authority that the authentication/recovery contract forbids. Separate delivery of recovery material, ability to reset, ability to log in and ability to cross MFA. Claim only the stages actually supported.

## Decision branches and limits

If a JWT is readable, that is not forgery. If recovery tokens expire in code but runtime clock/storage is unknown, state the gap. Verify one-time use atomically and bind account, purpose and intended session context; document whether existing sessions are expected to survive a reset.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
