# A01:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A01-01 — Object authorization

- Trace: Route/resolver -> identity -> record lookup -> policy -> serialization.
- Controlled verification: Compare one private disposable record with its owner and another controlled account; inspect fields and owner-side state.
- Discriminator: Private policy must be established; opaque IDs/public records do not prove a failure.
- Acceptance: Enforce policy before read/write; denied action exposes no protected fields and leaves state unchanged.

## A01-02 — Tenant queries and aggregates

- Trace: Tenant context -> query filter -> count/group/pagination -> export.
- Controlled verification: Compare two synthetic tenants in list, count and export outputs.
- Discriminator: An empty list does not establish isolated counts or exports.
- Acceptance: Apply tenant policy before aggregation/pagination; test both tenants and a legitimate export.

## A01-03 — Setup and privileged lifecycle

- Trace: Setup/invitation/role change -> caller authority -> persisted capability.
- Controlled verification: Use a controlled low-role account and an inert disposable invitation/role fixture.
- Discriminator: Hidden navigation is not enforcement; an already-admin caller is not privilege escalation.
- Acceptance: Central policy guards every lifecycle entry point; verify resulting roles directly.

## A01-04 — Authorization-sensitive caching

- Trace: Policy decision -> cache lookup/key -> response reuse across actors.
- Controlled verification: Warm a synthetic owner response, then request it from a different controlled identity.
- Discriminator: Equal bodies for intentionally public content are expected.
- Acceptance: Bind cached representation to relevant identity/tenant/policy context; verify cold and warm paths.

## A01-05 — Queues, subscriptions and batches

- Trace: Subscription creation/batch loader/worker -> current identity -> object set.
- Controlled verification: Test one controlled subscription or batch with mixed permitted/forbidden fixture objects.
- Discriminator: Connection authentication alone does not establish per-object authorization.
- Acceptance: Each object/action is authorized at the appropriate lifecycle point; denied elements do not leak.

## A01-06 — Server-side destination policy

- Trace: URL parse -> normalization -> DNS resolution -> redirect hops -> egress.
- Controlled verification: Use approved and disallowed owned callback fixtures; inspect every attempted destination.
- Discriminator: A caller-supplied public URL alone is not SSRF; keep internal endpoints out of the probe.
- Acceptance: Reject disallowed destinations before connection, including later redirects/resolutions.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
