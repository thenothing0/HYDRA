# security-windows-service-permissions-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect the low-privilege token/groups, service DACL/configuration, service account, executable/argument path and file/parent ACLs. Record the trigger that makes the service consume a change.

## Decisive experiment and source trace

Use read-only effective-access inspection or an inert owned replica. Determine whether the alleged actor can change the exact service setting or consumed file/path and whether a privileged service will actually use it under the stated trigger. Do not replace a real service binary or restart production for proof.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An unquoted path or readable executable alone is not escalation. The actor needs control of a viable consumed path/configuration; permissions on one directory may not apply to the relevant object.

## Repair acceptance

Remove the specific unintended edit authority at the service/file/parent boundary while preserving intended operators. Re-evaluate the low-privilege token and valid maintenance workflow.

## When the next edge is unavailable

If effective token, path ACLs or trigger are missing, list the missing chain edge and avoid a SYSTEM-compromise claim.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
