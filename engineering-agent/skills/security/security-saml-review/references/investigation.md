# security-saml-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read the service provider's actual XML/signature library, metadata trust, selected assertion, recipient/audience and request correlation. Identify the element whose verified subject becomes the session.

## Decisive experiment and source trace

Using owned local signing fixtures, trace whether the application consumes exactly the signed/validated assertion and the intended recipient/audience/time context. Compare a valid fixture, an invalid-signature fixture and an assertion for another local service provider; do not execute arbitrary XML gadgets.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A signed XML element somewhere in the document is not proof that the consumed identity is signed. Conversely, parsing XML or accepting multiple elements is not alone a wrapping exploit without selection and identity effect.

## Repair acceptance

Use supported library verification/selection and bind the consumed assertion to the intended service/session policy. Retest normal federation, invalid signature and the specific selection mismatch on the relevant library build.

## When the next edge is unavailable

When only metadata or an assertion sample exists, request the validation/identity-consumption code and keep acceptance unverified.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
