# Investigation: GraphQL subscription entitlement after connection setup

## Trace in the actual implementation

Trace authorization at subscribe time and each delivered event, including membership/session changes while the connection remains open.

## Implementation decisions

Record whether the contract requires immediate per-event reauthorization or bounded revocation propagation. Events queued before revocation need issuance/delivery timing. A still-open WebSocket without protected events is not continued access; separately test reconnect under the revoked identity.

## Discriminating verification

Subscribe with an owned account, revoke its synthetic resource entitlement, then emit one inert event; compare a still-entitled subscriber.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An open connection is not itself unauthorized data delivery; buffered already-authorized events require timing evidence.

## Repair acceptance

Revalidate or terminate according to policy and retest revocation, reconnect and entitled event delivery.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://graphql.org/learn/subscriptions/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
