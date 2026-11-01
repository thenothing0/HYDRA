# Investigation: Neo4j procedure/function execution and graph privilege delegation

## Trace in the actual implementation

Trace caller-controlled parameters through a permitted procedure into graph, file, network or process capabilities beyond the caller role.

## Implementation decisions

Resolve database/graph privileges alongside EXECUTE PROCEDURE/FUNCTION, boosted execution and procedure allowlist/unrestricted settings. A procedure name alone does not establish filesystem/network capability. Inspect its implementation and the effective caller role; compare an intentionally allowed read-only procedure with the restricted operation in an isolated graph fixture.

## Operational method

Retain the procedure signature/mode, installed implementation and effective grants. Ordinary EXECUTE permits invocation under applicable caller privileges; EXECUTE BOOSTED governs elevation and does not itself permit invocation. Elevated execution needs both grants for that procedure, subject to the deployed deny/mode rules. Separately, unrestricted registration is a configuration/implementation trust decision, not the user invocation grant. Compare invocation denied, ordinary execution and authorized boosted execution on an owned graph/trace; a procedure name or loading flag alone proves no file/network capability.

## Discriminating verification

Use an isolated synthetic graph and reviewed inert procedure; compare ordinary graph access with a forbidden delegated operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Procedure installation or an allowlist entry is not an exploit without caller reachability and a protected consumer.

## Repair acceptance

Constrain procedure implementation and execution privileges, verifying legitimate graph functionality and rejected delegation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://neo4j.com/docs/operations-manual/current/security/securing-extensions/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.

- [Additional implementation reference](https://neo4j.com/docs/operations-manual/current/authentication-authorization/dbms-administration/dbms-execute-privileges/)
