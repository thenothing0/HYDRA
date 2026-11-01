# security-command-injection-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace executable selection, shell use, argv boundaries, option handling, environment and working directory. Identify what the external utility does with each caller-controlled argument.

## Decisive experiment and source trace

Replace the executable with an inert local argv recorder using the same application construction path. Compare a normal filename with the suspected shell/option-boundary input, then inspect the actual argv and utility semantics. A recorder proves argument construction, not arbitrary command execution by the real utility.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

No shell does not mean no risk: a utility can interpret dangerous options or execute delegated functionality. Conversely, shell punctuation inside a single literal argument is not proof it became shell syntax.

## Repair acceptance

Avoid unnecessary shell parsing, fix executable/option authority and use supported argument separators where the actual utility supports them. Retest normal paths, original boundary case and required options in a bounded replica.

## When the next edge is unavailable

If only a command log exists, request the process API and target utility/version. Keep shell-control and argument/option-injection hypotheses separate.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
