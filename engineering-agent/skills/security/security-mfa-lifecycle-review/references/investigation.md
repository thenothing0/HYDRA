# security-mfa-lifecycle-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map pre-MFA and full sessions, factor enrollment/replacement, backup-code storage and recovery/alternate login. Record the required assurance for each sensitive action.

## Decisive experiment and source trace

Create an owned MFA account. With its password-stage session, attempt only an inert action whose policy requires full MFA, then compare with a completed-MFA session. Inspect whether factor replacement or recovery accidentally upgrades an incomplete session; test a single owned backup code for its declared one-use semantics.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A designed recovery flow is not a bypass merely because it uses a different factor. UI flags do not establish enrolled state or enforcement. Evaluate the actual assurance contract and durable factor/session effect.

## Repair acceptance

Enforce required assurance at the protected operation and bind enrollment/replacement/recovery to the intended account and challenge. Retest partial/full sessions and legitimate owner recovery.

## When the next edge is unavailable

If the assurance contract is unspecified, ask which actions require MFA while continuing to map session states. Keep claimed bypass impact conditional until that rule is known.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
