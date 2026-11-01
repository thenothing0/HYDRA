# Investigation: Persisted GraphQL operation admission and authorization

## Trace in the actual implementation

Trace who may introduce a query and whether registry admission is being mistaken for field/object authorization. Inspect alternate full-query and version paths.

## Implementation decisions

Separate automatic persisted-query registration from a strict allowlist: accepting a full query on a cache miss may be normal APQ. Admission hashes do not remove resolver authorization. Verify the configured profile before treating unregistered query execution as an allowlist bypass.

## Operational method

Retain the actual operation bytes, hash algorithm, computed hash, registry generation and principal permitted to register an operation. Compare a correct registry entry with a body/hash mismatch and a caller trying to replace a trusted operation ID. APQ fallback to full query may be intentional; neither a hash cache hit nor registration permission removes resolver/field authorization.

## Discriminating verification

In an owned schema compare an approved operation with one unregistered harmless operation and a restricted synthetic field.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Accepting arbitrary queries can be intentional; a known query hash does not grant resolver access and introspection alone proves no protected read.

## Repair acceptance

Enforce the declared admission policy and resolver authority independently, preserving approved client versions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://graphql.org/learn/security/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
