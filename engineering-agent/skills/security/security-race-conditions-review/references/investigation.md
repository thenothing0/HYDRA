# security-race-conditions-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Identify the shared invariant, read/check/commit locations, transaction isolation, lock/idempotency scope and retry behavior. Use a bounded local fixture for state-changing concurrency.

## Decisive experiment and source trace

Instrument the real operation with barriers to interleave two requests at the suspected check/use window. Compare serial execution and the controlled interleaving, observing the durable invariant rather than successful response counts. Record the schedule and final ledger/state.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Two 200 responses can correspond to one idempotent commit. A race in a simplified model is not proof the production transaction permits that schedule; retain that limitation.

## Repair acceptance

Make the invariant atomic using the platform's supported transaction/constraint/idempotency mechanism. Repeat the original schedule, serial legitimate use and retry/rollback control.

## When the next edge is unavailable

Without a safe isolated harness or authoritative state, provide a source interleaving proof and do not increase live concurrency to search for a race.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
