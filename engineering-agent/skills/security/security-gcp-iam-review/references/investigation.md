# security-gcp-iam-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Gather principal/permission/resource, hierarchy, inherited allow/deny and principal-boundary/condition context where applicable. Trace service-account delegation as its own authority path.

## Decisive experiment and source trace

Resolve one specified action on an owned resource using supported read-only analysis. For a service account, distinguish who can obtain/use its identity from what that identity can do, including required intermediate permissions and conditions.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An inherited role name alone is not an effective action proof. Conditional bindings and denials may defeat a path; reachability to an intermediate service account must not be assumed.

## Repair acceptance

Narrow the specific effective binding/delegation and preserve required workload operations. Re-evaluate the original tuple and a legitimate operation under the same hierarchy/context.

## When the next edge is unavailable

If ancestor or condition policy is absent, label the permission conclusion conditional and request the missing hierarchy edge.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
