# security-aws-iam-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect the specified principal/action/resource/context, identity and resource policies, trust/delegation path and applicable session, boundary and organization constraints. Use policy/version provenance.

## Decisive experiment and source trace

Resolve one concrete action against an owned resource using read-only policy analysis or a permitted simulator. Trace any role assumption separately from the assumed role's effective action. Compare an intended allowed action with the suspected excess grant and actual required conditions.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A wildcard Allow is not effective permission by itself. Explicit denials, boundaries, organization policies and service-specific authorization semantics can change the result; a simulator may omit runtime context.

## Repair acceptance

Narrow the evidenced effective permission or trust condition while preserving required workloads. Retest allowed operations and the original principal/action/resource tuple under the relevant constraints.

## When the next edge is unavailable

If organization/session/resource context is unavailable, give a conditional policy conclusion and request the specific missing constraint; do not assert account compromise from a policy fragment.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
