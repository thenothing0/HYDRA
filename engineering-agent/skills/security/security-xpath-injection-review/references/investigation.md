# security-xpath-injection-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Open XPath expression construction, namespace setup, variable bindings and the XML document/query consumer. Distinguish query construction from parser entity resolution.

## Decisive experiment and source trace

Use a tiny local XML fixture with public and private synthetic nodes. Compare a literal account/search value with the suspected expression input and inspect which nodes the evaluator selects. Follow later string interpolation even if the original XML storage was safe.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An XML parse error or entity-resolution issue is not XPath injection. Quoting characters in input prove nothing if the value is bound as a variable in the actual evaluator.

## Repair acceptance

Bind supported XPath variables or select from trusted expression structures and handle namespaces explicitly. Retest legitimate punctuation and the exact unauthorized node-selection case.

## When the next edge is unavailable

If expression construction/evaluator semantics are missing, request those artifacts; keep XXE and XPath hypotheses distinct.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
