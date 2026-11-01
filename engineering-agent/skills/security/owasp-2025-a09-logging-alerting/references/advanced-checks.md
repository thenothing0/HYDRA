# A09:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A09-01 — Auditable event production

- Trace: Security action -> structured event -> correlation/outcome -> collection.
- Controlled verification: Generate one labeled harmless test event and follow the same ID.
- Discriminator: Black-box silence does not prove missing internal logging.
- Acceptance: Required actions have usable complete events at the observed collector.

## A09-02 — Record and viewer integrity

- Trace: Untrusted field -> serialization -> parser -> storage -> rendered viewer.
- Controlled verification: Use inert newline/control-character fixtures and inspect record boundaries.
- Discriminator: Multiline raw text and forged parsed/viewed records are different effects.
- Acceptance: One untrusted field cannot create misleading trusted records in the actual reader.

## A09-03 — Secrets in exceptional logs

- Trace: Sensitive argument/exception -> logger formatting -> collector/export/access.
- Controlled verification: Use a unique synthetic secret marker on a controlled failure path.
- Discriminator: Do not print or search unrelated real secrets.
- Acceptance: Marker is absent from prohibited locations; useful redacted correlation remains.

## A09-04 — Rule evaluation and notification

- Trace: Event -> query/rule/version/window -> test sink -> receipt.
- Controlled verification: Use a test notification destination and record delivery delay.
- Discriminator: A source rule or logged event is not proof of notification delivery.
- Acceptance: Required signal reaches the intended test recipient inside the configured window.

## A09-05 — Collector loss and backpressure

- Trace: Producer -> queue/buffer -> retry/drop -> health signal -> recovery.
- Controlled verification: Use a local failing sink with bounded records.
- Discriminator: Do not fill live disks or flood collectors.
- Acceptance: Loss/backpressure matches policy and application guarantees survive the failure.

## A09-06 — Retention, integrity and access

- Trace: Log classification -> readers/writers -> retention/export -> incident use.
- Controlled verification: Review effective storage/access policy with supplied operator evidence.
- Discriminator: External testers cannot infer protected internal retention settings.
- Acceptance: Intended investigation evidence remains available and unauthorized readers/writers lack access.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
