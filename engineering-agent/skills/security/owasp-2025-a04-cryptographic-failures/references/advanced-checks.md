# A04:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A04-01 — Sensitive-data protection

- Trace: Collection -> transit -> cache/storage/export/backup -> deletion.
- Controlled verification: Use synthetic values and observable boundaries; internal storage remains unknown without evidence.
- Discriminator: Do not infer encryption-at-rest from HTTPS or cloud branding.
- Acceptance: Required properties hold across the actual data lifecycle, with documented key access.

## A04-02 — Peer identity and TLS trust

- Trace: Client connection -> trust store -> certificate/hostname check -> downstream service.
- Controlled verification: Observe the relevant authorized endpoint or test client with a dedicated trusted fixture CA.
- Discriminator: An edge connection says nothing about downstream verification; self-signed test trust can be deliberate.
- Acceptance: Invalid peer identity is rejected; a correctly trusted legitimate peer still connects.

## A04-03 — Password record and migration

- Trace: Password encoding API -> salt/work settings -> stored record -> verify/rehash.
- Controlled verification: Use controlled records supplied through source/test access; black-box inference stays limited.
- Discriminator: A string prefix and tiny timing sample are not an algorithm/work-factor audit.
- Acceptance: Current applicable guidance is documented; valid logins migrate safely and invalid passwords fail.

## A04-04 — Mode, nonce and authenticated failure

- Trace: High-level crypto API -> key scope -> nonce lifecycle -> decrypt consumer.
- Controlled verification: Alter synthetic ciphertext only in an approved fixture and inspect pre-use rejection.
- Discriminator: Random-looking output does not prove entropy or nonce uniqueness.
- Acceptance: Nonce requirements hold and integrity failure releases no usable plaintext or side effect.

## A04-05 — Key generation and custody

- Trace: Entropy source -> generation/import -> key store/access -> consumer.
- Controlled verification: Inspect supplied configuration/source and provenance; never try discovered keys externally.
- Discriminator: A code constant may be public/nonsecurity; establish key purpose and exposure.
- Acceptance: Security-relevant keys have suitable provenance and access; earlier weak material is replaced.

## A04-06 — Rotation and compromise response

- Trace: Format/key ID -> old/new readers -> re-encryption -> retirement/revocation.
- Controlled verification: Exercise synthetic old/new records and failure cases in a local migration fixture.
- Discriminator: Updating a generator does not repair secrets produced earlier.
- Acceptance: New writes use intended key; approved old reads work during migration; retired material loses authority.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
