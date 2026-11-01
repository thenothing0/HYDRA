# security-native-memory-safety-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace input-controlled sizes/indexes and object ownership through allocation, transfer, free and dereference. Record C/C++ build flags, ABI and reachable parser/entrypoint.

## Decisive experiment and source trace

Create a small local harness around the actual function with nonsecret bounded input. Use an available sanitizer/debugger to tie the failing access to object bounds/lifetime and preserve stack/source evidence. Compare a valid neighboring input and the repaired ownership/bounds behavior.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A crash is not automatically exploitable code execution. A sanitizer report in an unreachable harness path needs application reachability separately; absence of a report is not a safety proof.

## Repair acceptance

Repair the ownership/length invariant at its source, not merely suppress the symptom. Retest the original failure, valid edge inputs and cleanup using the same build identity.

## When the next edge is unavailable

Without a compiler/runtime, supply a precise source lifetime/bounds trace and label dynamic behavior unexecuted; do not invent sanitizer output.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
