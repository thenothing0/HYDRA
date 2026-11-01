# A02:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A02-01 — Initialization, upgrade and restore

- Trace: Bootstrap defaults -> persisted settings -> upgrade/restore override.
- Controlled verification: Observe fresh disposable instance and relevant upgrade state separately.
- Discriminator: A securely configured existing instance does not prove secure defaults.
- Acceptance: New instances start restricted and historical insecure persisted state is addressed explicitly.

## A02-02 — Configuration precedence

- Trace: Declared config -> environment -> runtime override -> active value.
- Controlled verification: Compare the known route behavior with effective deployment settings.
- Discriminator: Unused sample files and overridden fragments are not proof of runtime exposure.
- Acceptance: Change authoritative config and verify fresh deployment plus override behavior.

## A02-03 — Debug and administrative exposure

- Trace: Diagnostics/debug route registration -> ingress reachability -> auth policy.
- Controlled verification: Request a known in-scope diagnostic route and a controlled error.
- Discriminator: A generic error or version banner alone may not expose a protected capability.
- Acceptance: Restrict administrative surfaces; client errors avoid secrets while operator correlation remains.

## A02-04 — Ingress and forwarded-header trust

- Trace: Proxy trust config -> caller IP/host/origin interpretation -> sensitive decision.
- Controlled verification: Use controlled requests within the documented ingress model; compare spoofed and trusted context.
- Discriminator: Trusted proxy values may be legitimate only on the actual trusted hop.
- Acceptance: Untrusted direct callers cannot override security-relevant origin/address context.

## A02-05 — Parser capability settings

- Trace: XML/format parser construction -> external resolution/expansion flags -> input.
- Controlled verification: Use an inert local fixture to observe prohibited feature activation.
- Discriminator: Feature names in dependencies do not prove enabled runtime behavior.
- Acceptance: Disable unnecessary unsafe capabilities and verify supported legitimate documents.

## A02-06 — Storage and client security policy

- Trace: Effective resource permissions/response directives -> consumer -> protected asset.
- Controlled verification: Evaluate actual policy and minimal known fixture access; inspect browser context as relevant.
- Discriminator: Missing headers and permissive fragments need context and effective deny-rule evaluation.
- Acceptance: Required exposure boundaries hold after redeploy; permitted content remains usable.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
