# security-native-integer-safety-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Track each attacker-influenced count/length across signedness, width conversions, arithmetic, allocation and copy/iteration. Record ABI and actual operand/result types.

## Decisive experiment and source trace

Using an isolated local harness, choose a small boundary case that demonstrates disagreement between validated size and used size without allocating huge memory. Record intermediate typed values and any sanitizer result. Distinguish defined unsigned wrap from signed overflow and conversion issues.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A mathematical overflow prediction using the wrong promoted type is not proof. The default undefined-behavior sanitizer set does not cover every unsigned/conversion issue; a clean run is not universal validation.

## Repair acceptance

Use checked arithmetic and validate before narrowing/allocation/use under the intended type contract. Retest maximum legitimate sizes, rejection boundary and original allocation/copy agreement.

## When the next edge is unavailable

If ABI or type definitions are missing, request them and keep the arithmetic conclusion conditional.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
