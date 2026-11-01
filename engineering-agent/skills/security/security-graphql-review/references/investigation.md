# security-graphql-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect schema and resolver mappings for a protected node, global node lookup, nested relationship, mutation and subscription. Establish policy on the resolved object and sensitive fields.

## Decisive experiment and source trace

Resolve private synthetic node B through the ordinary field and the global node/relationship path as actor A. Use the same B identifier and A context. For a subscription, inspect how identity and entitlement changes are applied to later events; do not assume handshake authorization covers each resource.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Introspection, aliases, batching and query depth are features. They establish a vulnerability only when tied to unauthorized bytes/effects or an evidenced resource-budget failure. Keep distinct resolver root causes in separate reports.

## Repair acceptance

Apply the relevant object/field/function policy at the resolver or shared data boundary; ensure loaders and caches retain actor/tenant isolation. Retest the original path, another path to the same node and an entitled query.

## When the next edge is unavailable

Without resolver code or two controlled identities, keep schema-derived paths as candidates and identify the precise field/object policy needed next.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
