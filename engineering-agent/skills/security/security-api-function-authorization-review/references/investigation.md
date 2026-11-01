# security-api-function-authorization-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read route registration, method dispatch, capability middleware and service entrypoints. Identify a real operation restricted to a role, rather than an administrative-looking URL.

## Decisive experiment and source trace

With an owned fixture resource, compare a viewer calling a restricted publish action against an editor calling the same action. Keep the resource and payload constant. Trace whether an alternate version or worker invokes the same service without the capability gate. Record publication state or an operation audit event after both successful and error responses.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

The viewer being forbidden from another owner's object is object authorization, not proof that the whole function is forbidden. A hidden UI button or an HTTP method difference alone establishes neither policy nor effect.

## Repair acceptance

Enforce the required capability at the shared operation boundary while preserving necessary object/tenant checks. Verify denied actors cannot commit through any evidenced entrypoint and the editor can still publish.

## When the next edge is unavailable

If roles are named but their entitlements are absent, request the operation/role contract. Continue tracing middleware coverage without assigning a privilege escalation severity.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
