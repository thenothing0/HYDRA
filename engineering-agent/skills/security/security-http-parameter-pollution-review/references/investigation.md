# security-http-parameter-pollution-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Identify the raw parameter encoding and each proxy/framework/validator/consumer parser. Record whether duplicate keys are first, last, list or rejected at each relevant layer.

## Decisive experiment and source trace

In an owned fixture send one normal parameter, then one duplicate-key case derived from the parser chain. Capture both the value authorized/validated and the value consumed by the protected operation. Keep framing and unrelated parameters fixed.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Duplicate acceptance is not a vulnerability when every layer agrees or the field is intentionally multi-valued. A different echoed value alone is not a violated authorization/business rule.

## Repair acceptance

Define one supported multiplicity/normalization contract and enforce the same interpreted value at validation and use. Retest normal single and intended multi-value inputs plus the original disagreement.

## When the next edge is unavailable

Without parsed values from both relevant layers, record the ambiguity and request parser configuration or a local trace; do not spray duplicate combinations.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
