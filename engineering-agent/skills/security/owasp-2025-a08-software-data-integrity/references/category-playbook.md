# A08:2025 — operating playbook

## Source review

Find every transition where external bytes select code, object types, critical fields or updates. Inspect exact signed bytes, trusted key selection, signer authorization, nested deserializers, verification-before-use, field allowlists and replay storage. Avoid turning an authenticated outer wrapper into trust in unsafe inner content.

## Authorized bug bounty / external verification

Use a local or controlled signed-message/update fixture. Change one protected field, present an unauthorized authority, and replay only where the business contract requires one-time processing. For deserialization, use static type/constructor traces and benign rejected inputs; no gadget execution is needed to establish the unsafe boundary.

## Minimum evidence for confirmation

Untrusted/altered data is accepted as authoritative, or a complete reachable source trace establishes unsafe object construction or forbidden field assignment. Observe side effects, not just parsing or a success response.

## Decision branches and limits

HMAC tests do not validate public-key trust stores. A valid signature is not authorization, freshness or safe schema. If the root cause is governance of a build system, classify primarily under A03 and cross-reference the concrete integrity failure instead of double counting.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
