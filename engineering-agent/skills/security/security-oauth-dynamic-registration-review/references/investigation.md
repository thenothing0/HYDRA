# Investigation: Dynamic client registration metadata authority

## Trace in the actual implementation

Determine who may register or modify clients and whether untrusted metadata becomes a trusted redirect, fetch destination or privileged client classification.

## Implementation decisions

A software statement may authenticate selected metadata, not every caller-supplied field. Inspect registration update authority separately from creation. Open registration and public client classification may be intentional; escalating to a confidential/trusted client or changing another client requires a distinct observed grant.

## Operational method

Record any initial-access credential used for creation and the registration-access credential/client URI issued for subsequent management. Those credentials have different scopes and are not interchangeable. Compare updating the created synthetic client with attempting the same operation on a second client; successful open registration alone is not proof of cross-client update authority or confidential-client trust.

## Discriminating verification

Use an owned local issuer and client; compare permitted registration with one unauthorized metadata mutation and inspect the effective registered client.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Open registration can be intentional. A client identifier or reflected metadata is not client impersonation or a protected server-side fetch.

## Repair acceptance

Constrain metadata and client class changes at registration/update, then verify intended public clients and rejection of privileged metadata.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc7591)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
