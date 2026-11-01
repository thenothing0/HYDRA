# A05:2025 — operating playbook

## Source review

Trace untrusted values and structural selectors separately to SQL/NoSQL, templates, process calls and HTML/DOM sinks. Inspect decoding order, stored input later consumed by a job/export, raw ORM APIs, dynamic operators and renderer context. Use existing test fixtures or instrument a sink where direct execution would be risky.

## Authorized bug bounty / external verification

Establish a baseline with legitimate input, then an inert context-relevant probe on controlled data. Confirm syntax interpretation through a bounded differential or local reproduction. Avoid bulk payload sprays, long time delays and data extraction. In XSS, prove a controlled DOM effect in an isolated account/page; do not read credentials or affect other users.

## Minimum evidence for confirmation

User-controlled data changes interpreter semantics in a reachable relevant context, or a complete source-to-sink trace establishes this. Record the context and transformations. A reflected string, template delimiter, database error or WAF block alone cannot establish execution.

## Decision branches and limits

Patch the sink with the API appropriate to its context and test legitimate quotes/Unicode plus structural choices. A fixed executable with argument arrays can still accept unsafe user-selected options. A WAF/CSP outcome and a source-code repair are different evidence.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
