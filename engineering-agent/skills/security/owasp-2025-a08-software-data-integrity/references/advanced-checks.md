# A08:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A08-01 — Exact-byte authenticity

- Trace: External bytes -> canonical/signed representation -> verification -> consumer.
- Controlled verification: Change one protected fixture field and inspect rejection before effects.
- Discriminator: Encoding/checksums from the same untrusted source do not establish authenticity.
- Acceptance: Verification covers consumed meaning and happens before trusted processing.

## A08-02 — Trusted signer and key selection

- Trace: Key source -> allowed signer -> artifact/message purpose -> policy.
- Controlled verification: Use a different synthetic authority for an otherwise valid fixture.
- Discriminator: A mathematically valid signature is not signer authorization.
- Acceptance: Only approved authorities for the intended purpose can produce accepted content.

## A08-03 — Nested object construction

- Trace: Outer wrapper -> nested decoder -> type resolution/hooks -> privileged use.
- Controlled verification: Use source traces and inert type/schema violations.
- Discriminator: A signed wrapper does not make unsafe object construction safe.
- Acceptance: External bytes cannot select dangerous constructors or hooks outside the constrained data contract.

## A08-04 — Server-managed property binding

- Trace: Input schema -> model/DTO mapping -> caller writable fields -> persistence.
- Controlled verification: Submit a harmless forbidden property to a controlled record and read it back.
- Discriminator: Parsing or ignoring an extra property is not successful mass assignment.
- Acceptance: Only permitted properties change; explicit server-managed state remains authoritative.

## A08-05 — Freshness and one-time processing

- Trace: Authenticated content -> time/operation ID -> atomic replay store -> side effect.
- Controlled verification: Replay only an operation declared one-time, within controlled scope.
- Discriminator: Message authenticity alone does not imply replay resistance.
- Acceptance: Duplicate/stale authority cannot repeat an effect where the contract forbids it.

## A08-06 — Plugin/update/artifact consumption

- Trace: Trusted update identity -> download/storage -> verification -> executable load.
- Controlled verification: Inspect supplied artifacts and benign local installer fixtures.
- Discriminator: A source URL alone is not evidence of unsafe updating.
- Acceptance: Unapproved/modified bytes reject before load; rollback/downgrade behavior matches policy.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
