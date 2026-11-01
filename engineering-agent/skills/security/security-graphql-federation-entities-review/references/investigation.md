# Investigation: GraphQL federation entity representation trust

## Trace in the actual implementation

Follow __typename/key representations into the actual entity loader and tenant policy. Separate gateway authentication from direct subgraph reachability.

## Implementation decisions

Identify whether the subgraph trusts a gateway-authenticated principal or an unauthenticated representation. An entity key is an object locator, not a tenant grant. Preserve the same requester context when comparing gateway and direct-subgraph paths; an internal service call is not automatically attacker reachable.

## Operational method

Inspect the subgraph context constructor and which authenticated gateway/end-user/tenant claims it receives. Retain the entity representation fields actually resolved; a gateway service identity must not substitute for user entitlement when resolving an untrusted representation. Compare the same synthetic entity through gateway and directly reachable subgraph paths using the same intended user authority, and leave direct reachability unproved if it is absent.

## Discriminating verification

Use two owned entity records and a local gateway/subgraph fixture; compare rightful resolution with a foreign synthetic representation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An entity key in a schema is not access; a direct subgraph blocked by service authentication does not establish a reachable public defect.

## Repair acceptance

Bind entity resolution to requester/tenant authority and verify both gateway and permitted service paths.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.apollographql.com/docs/federation/entities)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
