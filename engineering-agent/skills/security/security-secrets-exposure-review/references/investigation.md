# security-secrets-exposure-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Establish secret type/owner, source/build/log location, intended audience, reachable recipient and rotation/revocation state using nonsecret metadata. Do not print or test real values against services.

## Decisive experiment and source trace

Trace a supplied candidate through artifact distribution and consumer trust. Distinguish a public client identifier, test fixture and real credential using issuer/owner documentation or approved offline context. Record only redacted bytes/fingerprint and who can access the exposure.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Entropy or a key-like prefix is a lead, not proof of a valid credential. A real secret in a properly protected owner vault is not unintended exposure; a stale credential may still require cleanup without current compromise claims.

## Repair acceptance

Remove the exposure path and have the owner rotate/revoke according to the actual credential lifecycle; deleting a current file does not erase previous distributed artifacts. Retest with a synthetic marker and owner-confirmed lifecycle state.

## When the next edge is unavailable

If validity/ownership is unknown, keep it as a candidate and request safe owner confirmation; do not validate by making authenticated third-party calls.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
