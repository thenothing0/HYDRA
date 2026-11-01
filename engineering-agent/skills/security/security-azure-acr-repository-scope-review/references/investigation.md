# Investigation: Azure Container Registry repository-scoped publication and consumption

## Trace in the actual implementation

Resolve allowed content/metadata actions at a repository and trace whether lower-trust publication affects an approved workload image.

## Implementation decisions

Distinguish registry-wide roles, repository permissions and the actual permission mode supported by this registry. A token scope map governs named repository actions, not downstream deployment trust. Determine whether a lower-trust producer can replace the digest consumed by a protected release; being able to push its own independent repository is an expected control.

## Operational method

Read roleAssignmentMode before interpreting role names. In RBAC Registry+ABAC Repository Permissions mode, legacy AcrPull/AcrPush/AcrDelete grants are not honored; inspect repository reader/writer/contributor roles and their ABAC conditions, and catalog-list/control-plane rights separately. A data role without an ABAC condition may apply registry-wide. Compare the same pull/push operation on an intended repository and a nonmatching repository using supplied policy/trace or an isolated policy fixture.

## Discriminating verification

Use an owned registry/local fixture and synthetic image metadata; compare authorized repository action with a different repository or release tag.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Registry login or pull from an intentionally shared repository is not cross-repository write or deployment compromise.

## Repair acceptance

Constrain repository actions and pin deployment provenance/digest, then verify authorized producer and reader workflows.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-overview)
- [Additional implementation reference](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-abac-repository-permissions)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
