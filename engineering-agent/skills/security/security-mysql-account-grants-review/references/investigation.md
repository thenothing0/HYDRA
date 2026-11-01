# Investigation: MySQL effective account/host matching and stored-object privileges

## Trace in the actual implementation

Resolve the actual authenticated account and effective active roles before following a stored routine/view into protected tables.

## Implementation decisions

Resolve the matched user@host account, active roles and direct grants before invoking stored-object authority. SQL SECURITY DEFINER may deliberately delegate a narrow operation; inspect definer identity, object body and caller-controlled arguments only when that path is reachable. A client-supplied username alone does not identify the effective server account.

## Discriminating verification

Use an isolated database with two owned users and synthetic rows; compare intended access and a controlled definer-object invocation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A broad grant on a different host account or inactive role is not effective access for the tested connection.

## Repair acceptance

Constrain matched account and stored-object authority, testing normal routines and restricted table operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://dev.mysql.com/doc/refman/8.4/en/access-control.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
