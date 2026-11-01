# security-redis-acl-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect Redis version, effective ACL user/selectors, command/key patterns, Pub/Sub rules and actual application command forms. Distinguish key authority from channel authority.

## Decisive experiment and source trace

Using an owned instance/fixture, compare an allowed tenant key and channel with prohibited tenant markers under the same ACL user. Inspect commands that accept multiple keys and the version-specific ACL evaluation path; avoid destructive flush/config operations.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A broad command category is not alone a cross-tenant read if key patterns constrain the operation. Key patterns do not automatically prove Pub/Sub channel isolation.

## Repair acceptance

Narrow command, key and channel authority using supported version-specific ACLs. Retest legitimate app commands, denied cross-tenant keys/channels and any originally evidenced multi-key path.

## When the next edge is unavailable

Without effective ACL/version or the actual command form, request that context and keep policy snippets conditional.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
