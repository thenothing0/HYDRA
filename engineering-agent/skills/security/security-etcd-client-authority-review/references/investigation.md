# Investigation: etcd client authentication and key-prefix authorization

## Trace in the actual implementation

Follow verified client identity into effective key-prefix operations and distinguish server transport trust from enabled application authorization.

## Implementation decisions

Confirm authentication is enabled and which certificate or token maps to the effective user and roles. Prefix range permissions depend on the actual byte interval, not a human-readable prefix label. A TLS connection is not an authorization check; use tiny owned keys and inspect both point and range operations without dumping the keyspace.

## Discriminating verification

Use an isolated etcd fixture with synthetic prefixes and two owned clients; compare rightful read/write and a restricted prefix operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

TLS connection success is not key authorization, and endpoint metadata is not confidential key-value exposure.

## Repair acceptance

Bind client identities and prefix grants consistently across enabled interfaces and verify intended operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://etcd.io/docs/v3.6/op-guide/authentication/rbac/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
