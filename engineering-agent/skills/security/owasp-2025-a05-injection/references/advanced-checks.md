# A05:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A05-01 — SQL/NoSQL query data

- Trace: Input -> decoding -> query builder -> bound values -> selected fixture data.
- Controlled verification: Compare legitimate and inert syntax-changing terms on synthetic records.
- Discriminator: Errors or WAF blocks alone do not establish changed interpreter semantics.
- Acceptance: Untrusted values remain data; valid punctuation/Unicode keep working.

## A05-02 — Query structural selectors

- Trace: Sort/field/operator/date-part selector -> mapping -> raw ORM or backend API.
- Controlled verification: Use permitted and unmapped selectors against a controlled feature.
- Discriminator: Value parameterization does not automatically protect identifiers/operators.
- Acceptance: Only trusted structural choices reach the interpreter; unsupported choices reject safely.

## A05-03 — HTML and DOM rendering

- Trace: Stored/reflected input -> transforms -> template/DOM sink -> actual context.
- Controlled verification: Prove a harmless controlled DOM effect in an isolated account/page.
- Discriminator: Reflection as escaped text is not XSS; do not read real session data.
- Acceptance: Context-correct handling prevents execution while preserving required text/rich content.

## A05-04 — Commands and arguments

- Trace: Executable selection -> shell/argument API -> option parsing -> invoked operation.
- Controlled verification: Use a stub executable or local instrumentation to inspect the argument vector.
- Discriminator: Array arguments can still expose dangerous caller-selected options.
- Acceptance: Executable/structure and unsafe options remain trusted; data arguments cannot gain command authority.

## A05-05 — Template, expression and filter sinks

- Trace: Input -> template/filter construction -> evaluation engine -> output.
- Controlled verification: Use inert local sentinel interpretation and a legitimate control.
- Discriminator: A delimiter in output is not proof it was evaluated.
- Acceptance: External content is rendered as data or handled by a deliberately constrained supported feature.

## A05-06 — Second-order interpreter use

- Trace: Write/import -> stored value -> background job/report/export -> interpreter.
- Controlled verification: Save an inert sentinel then inspect its later consumer in a disposable fixture.
- Discriminator: A safe insertion path does not prove safe later interpretation.
- Acceptance: All reachable later consumers preserve data/instruction separation.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
