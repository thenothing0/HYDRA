# security-kafka-acl-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read principal mapping, authentication, effective broker/controller authorizer configuration, ACL patterns and topic/group/transactional-resource use. Record cluster/version.

## Decisive experiment and source trace

On an owned fixture cluster or supplied authorization trace, compare an intended produce/consume operation with a prohibited topic or consumer-group operation under the same principal. Resolve literal/prefixed pattern and operation semantics for that exact resource.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A topic ACL alone does not establish consumer-group authority. A permissive-looking ACL fragment may not be effective under the actual authorizer and other decisions.

## Repair acceptance

Bind principal, resource pattern and operations to the tenant contract and preserve necessary client behavior. Retest allowed produce/consume, denied cross-tenant tuple and group lifecycle.

## When the next edge is unavailable

If authorizer/principal mapping or group context is absent, request it rather than infer data consumption from an ACL listing alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
