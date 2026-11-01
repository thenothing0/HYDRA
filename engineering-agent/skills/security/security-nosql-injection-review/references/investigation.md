# security-nosql-injection-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect accepted input types, JSON decoding, selector construction and the actual database query API. Separate intended advanced-query capability from ordinary scalar fields.

## Decisive experiment and source trace

In a local dataset compare a valid scalar filter with a caller-supplied structured value at the exact affected field. Observe the final selector/operator interpretation and selected synthetic records. Follow validation through wrappers or JSON re-decoding to establish whether the database receives the structure.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An operator-looking string stored as a literal is not query control. Rejecting an object at schema validation defeats that path. A user-authorized query console needs its own capability contract.

## Repair acceptance

Enforce the intended scalar/structured schema and construct trusted selectors explicitly. Retest valid scalar queries, wrong types and the original operator path without removing intended search functionality.

## When the next edge is unavailable

Without driver/API behavior, report the type/selector candidate and request a final query trace or local fixture; do not assume every NoSQL engine interprets the same operators.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
