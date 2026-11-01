# security-postgres-rls-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read table policies, USING/WITH CHECK, table ownership, bypass roles, security-definer functions and connection-pool tenant context. Identify the real application role.

## Decisive experiment and source trace

In a disposable database run A/B synthetic row reads and writes as the actual-equivalent application role, then switch tenant context over a reused connection. Compare with an entitled role. Test both old-row visibility and proposed-row acceptance where the operation requires them.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A superuser or table owner result may not represent the application role. Testing only SELECT does not establish INSERT/UPDATE confinement, and a source policy without effective role settings does not prove enforcement.

## Repair acceptance

Apply policies to intended roles/actions and establish/reset trustworthy tenant context on pool reuse. Retest denied rows/writes, legitimate A/B operations and the original connection lifecycle.

## When the next edge is unavailable

If real role/pool context is missing, provide conditional policy analysis and request those specifics before concluding cross-tenant exposure.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
