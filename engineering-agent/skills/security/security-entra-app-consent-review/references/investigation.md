# security-entra-app-consent-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect app/service-principal identity, tenant, consent/grants, token type/claims and the resource API's enforcement. Distinguish delegated scopes from application roles.

## Decisive experiment and source trace

Trace one protected API operation under an intended delegated or app-only context, then compare an owned wrong-tenant or insufficient-grant fixture. Determine whether the API uses the correct grant semantics and caller/account binding rather than merely checking that a token is signed.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Admin consent or a broad permission listing is not proof the application exercises unintended authority. A delegated token and an app-only token cannot be evaluated with interchangeable assumptions.

## Repair acceptance

Enforce the intended tenant, issuer, token purpose and operation-specific scope/role, and narrow unnecessary grants. Retest the legitimate integration and the evidenced wrong context.

## When the next edge is unavailable

Without resource API validation code and grant/token context, report consent inventory and the missing enforcement edge only.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
