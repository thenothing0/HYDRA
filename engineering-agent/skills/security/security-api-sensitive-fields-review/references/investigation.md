# security-api-sensitive-fields-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect serializer/projection definitions, resolver fields, API schema and the field visibility rule for each actor. Separate read authority from field write authority.

## Decisive experiment and source trace

Use an object actor A may legitimately read. Populate a synthetic private field as its owner and request the ordinary view, expanded view and the one alternate serializer evidenced in source. Check raw wire output and nested relationships, not just the rendered UI. Repeat as the actor entitled to that field.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An internal field name in a schema is inventory. A null, masked or absent value does not demonstrate exposure. Reading an entirely forbidden object is BOLA; modifying a protected property is mass assignment.

## Repair acceptance

Use explicit actor-aware response projections at serialization and export boundaries. Test allowed public fields, the denied private marker and authorized private-field access after the change.

## When the next edge is unavailable

When field sensitivity is undocumented, request the visibility contract or owner confirmation; do not treat every extra JSON property as confidential.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
