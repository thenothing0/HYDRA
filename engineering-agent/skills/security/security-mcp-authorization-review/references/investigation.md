# security-mcp-authorization-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Record protocol/transport, MCP client/resource/authorization server identities, token resource/audience, per-client consent and downstream credential path. Treat stdio and remote transports according to their actual design.

## Decisive experiment and source trace

With owned local fixtures compare the intended client/resource token and consent against a wrong-resource or wrong-client context at the real validation gate. Trace whether a proxy passes a token to an unintended downstream resource or reuses consent for an unrelated client.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A trusted connection is not authority for every operation. A synthetic token fixture tests gate logic only; it does not prove a real authorization server issued or a remote server accepted the same token.

## Repair acceptance

Validate resource/client/actor context, bind consent and use appropriate downstream delegation under the current protocol contract. Retest intended integration, wrong audience/client and revoked consent.

## When the next edge is unavailable

If transport/version or token validation path is missing, request it and avoid imposing a remote OAuth assumption on a local stdio integration.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
