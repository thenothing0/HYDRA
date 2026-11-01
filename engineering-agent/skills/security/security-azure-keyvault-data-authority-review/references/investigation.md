# Investigation: Key Vault control-plane versus secret/key data-plane permissions

## Trace in the actual implementation

Resolve the actual principal and management versus data permissions. Follow which actions expose secret values or allow signing/decryption rather than only listing metadata.

## Implementation decisions

Identify the vault permission model: Azure RBAC and legacy access policies have different evaluation paths. Control-plane visibility is distinct from secret values or key cryptographic operations, but a policy-management grant may create a delegation path. Evaluate that path from supplied assignments/source without granting roles or retrieving real secrets merely to demonstrate it.

## Discriminating verification

Use an owned vault with synthetic content; compare the intended data operation and a restricted owned role/version.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Vault discovery or management-plane read is not secret-value access; report the specific successful data operation.

## Repair acceptance

Limit data-plane authority and delegation changes, retesting value access, versions and permitted operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
