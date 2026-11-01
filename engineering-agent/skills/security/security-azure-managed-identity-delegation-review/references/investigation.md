# Investigation: Azure managed identity delegation through a workload-controlled operation

## Trace in the actual implementation

Trace who can cause the workload to act and which identity/resource scope it uses. A platform identity endpoint is not independently an authorization flaw.

## Implementation decisions

Map the caller-controlled operation to the workload identity it uses and the exact resource action. Access to a metadata endpoint inside an owned workload is not itself a confused-deputy finding. Determine which identities the workload can select and whether its public API constrains destination, tenant and action before using the ambient identity.

## Operational method

Record system-assigned versus user-assigned identity, the actual token endpoint and selector supported by that workload, and who can attach/select identities. Follow a caller input through endpoint selection into the token resource/audience and final Azure action. In a stub, expose two identity handles with disjoint permissions and verify that caller-controlled identity selection cannot borrow the stronger one. Endpoint reachability alone does not establish an unauthorized delegated operation.

## Discriminating verification

Use an owned workload fixture and synthetic resource; compare its intended operation with a caller-selected out-of-policy resource/action.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Obtaining identity metadata or a correctly scoped denied token does not prove broader Azure resource access.

## Repair acceptance

Constrain workload delegation and assigned permissions, then verify legitimate calls and resource/audience rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
