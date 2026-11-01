# security-jwt-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Open token issuance, verifier configuration, key source, claim validation and downstream account lookup. Distinguish access, ID, reset and other token purposes even when they share a signer.

## Decisive experiment and source trace

With local nonsecret keys and synthetic claims, compare a valid intended token against one correctly signed token for a different issuer/audience/purpose and one invalid signature. Trace the exact verifier-to-account consumer. When inspecting key selection, determine whether untrusted token metadata can choose a trust anchor, not merely a key identifier in a trusted set.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Decoding a token is not signature verification. A signed token with a harmless unused claim is not a bypass. Do not claim real cross-service acceptance from a standalone mocked verifier.

## Repair acceptance

Bind verification to the expected issuer, audience, purpose and allowed key/algorithm source; enforce the declared expiry/revocation contract at the consumer. Retest intended and cross-purpose tokens plus key rotation compatibility.

## When the next edge is unavailable

If only decoded claims are supplied, request verifier configuration and consumer code. Token text alone cannot establish acceptance or account authority.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
