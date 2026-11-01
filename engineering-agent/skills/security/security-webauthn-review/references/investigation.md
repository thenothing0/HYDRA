# security-webauthn-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect registration/authentication option generation, challenge persistence/consumption, RP/origin configuration, verification library and credential-to-account storage.

## Decisive experiment and source trace

Use owned test authenticators/accounts. Compare a normal ceremony with an expired/reused challenge and a response associated with the wrong local account. Trace verified credential identity and required user verification to the account session; preserve actual authenticator and browser prerequisites.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A counter anomaly alone is not universal proof of a cloned passkey. Platform/synced credential behavior and the relying party's threat model matter; do not infer authentication bypass from decoded client data.

## Repair acceptance

Use supported verification of the intended RP/origin/challenge and bind credential/account/purpose with one-use transaction state. Retest valid registration/login, the evidenced wrong binding and the declared user-verification requirement.

## When the next edge is unavailable

Without verifier code or a supported authenticator/runtime, complete the source trace and identify the ceremony behavior not executed.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
