# security-session-lifecycle-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read session issuance/rotation, cookie/token binding, refresh-family state and logout/revocation. Determine what invalidation the product promises after login, privilege change, reset and logout.

## Decisive experiment and source trace

Track two owned sessions and exact identifiers across one declared transition. Compare the prior session's access to a protected fixture before/after that transition, then check the new intended session. For fixation, prove that an attacker-influenced preauth identifier survives into a victim-authorized session; identifier equality alone is incomplete.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A stateless token remaining valid until its documented short expiry is not automatically a broken logout promise. A browser deleting its cookie is different from server-side revocation.

## Repair acceptance

Implement the declared rotation/revocation boundary and atomically constrain refresh reuse where required. Retest the original prior credential, replacement session and unrelated valid sessions under that policy.

## When the next edge is unavailable

If session policy is missing, report the observed lifetime and request the promised invalidation rule rather than inventing one.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
