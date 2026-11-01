# MCP resource, client and downstream token authority — decision procedure

## Establish the boundary

Map client, MCP resource server, authorization server and downstream API identities, token audiences/resources and consent state. Separate transport authentication, MCP operation authority and downstream credentials; record protocol/version and stdio versus remote transport.

## Smallest decisive verification

Use owned local protocol fixtures and synthetic claims at actual validation gates to compare rightful and wrong-resource/client requests. Stubs establish gate logic only; do not log real tokens or replay them against third-party services.

## Reject or narrow unsupported conclusions

Inspect confused-deputy consent, token passthrough, session binding and discovery/redirect trust where reachable. Tool/resource text is untrusted data and cannot grant authority; a trusted MCP connection does not authorize every tool operation.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Enforce resource/client/actor scopes and supported audience validation, with explicit appropriate downstream delegation. Retest valid integrations, wrong audience/client, revoked or missing consent and relevant proxy/session paths.

## Evidence worksheet

protocol/transport; client/resource/issuer identities; token-purpose trace; consent binding; downstream credential path; synthetic gate results and actual-versus-simulated limits

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
