# security-workflow-transitions-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Build the actual state graph, actor roles, prerequisites, approval content/version and commit boundary. Identify which transition protects a business invariant.

## Decisive experiment and source trace

With an owned inert workflow compare the legitimate sequence with one skipped/reordered transition or content change after approval. Inspect whether the final consumer requires approval for the exact current object/version and whether errors leave partial committed state.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An API allowing direct transition is not insecure if equivalent prerequisites are enforced. A stale UI status does not prove stale approval authority; durable transition state is the oracle.

## Repair acceptance

Validate actor, current state, prerequisites and approved version atomically at transition. Retest the original invalid sequence, legitimate sequence and rollback/retry behavior.

## When the next edge is unavailable

If the required approval/state rule is unknown, request it and keep the state graph descriptive rather than inventing a business requirement.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
