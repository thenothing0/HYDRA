# security-grpc-authorization-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Open service definitions, interceptor registration, gateway mappings and stream handlers. Locate the trusted principal and the point each message selects its resource.

## Decisive experiment and source trace

Use an owned unary request as the positive control. In a local/authorized stream send one permitted fixture object, then one other-tenant fixture identifier without changing the session. Trace whether only stream establishment is checked while the second message is consumed with service authority. Compare the actual protected reply or state.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A gRPC status or a generated stub revealing a method name is not proof. Metadata supplied by a caller is not trusted identity unless the actual transport/verification path establishes it.

## Repair acceptance

Cover unary and streaming entrypoints with authenticated context, then authorize each resource-sensitive message as required by policy. Retest valid streams, denied later messages and cancellation cleanup.

## When the next edge is unavailable

If only protobuf files exist, report the service inventory and missing interceptor/handler implementation; do not declare absent authorization from the schema alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
