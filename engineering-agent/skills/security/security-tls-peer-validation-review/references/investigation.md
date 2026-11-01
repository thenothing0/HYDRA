# security-tls-peer-validation-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect the actual TLS client configuration, trust store, reference hostname, SNI, redirect/proxy behavior and fallback branches. Record library/version and verification overrides.

## Decisive experiment and source trace

Use local owned TLS fixtures: trusted matching peer, untrusted peer and wrong-name peer. Observe whether the application sends/accepts protected fixture data after each handshake, not simply whether a TCP connection opens. Preserve intended hostname when evaluating custom resolution.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Encryption alone does not authenticate the intended peer. A test using a different client/configuration is not evidence for the application, and a failed local fixture without a working valid control is inconclusive.

## Repair acceptance

Enable supported chain and reference-identity validation at the real client without insecure fallback. Retest valid peer, untrusted/wrong-name peers and the original proxy/redirect path.

## When the next edge is unavailable

If client construction or peer identity is missing, request it; avoid inferring application verification from server certificate properties alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
