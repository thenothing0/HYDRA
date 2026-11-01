# Investigation: Entra tenant-independent issuer templates and tenant-stable principal mapping

## Trace in the actual implementation

Trace which external tenants may authenticate and which local organization their principals may access. Do not confuse cryptographic validity with tenant admission.

## Implementation decisions

Bind tid, issuer and client/resource audience using the actual multi-tenant validation rules and tenant enrollment policy. A token signed by a Microsoft key can still originate from an unintended tenant. Supporting multiple tenants is legitimate; show a protected tenant operation accepted for an unassociated identity rather than treating common metadata endpoints as a defect.

## Operational method

For tenant-independent metadata, resolve the configured issuer template using the validated tid under the selected token-version/issuer rules; do not accept an arbitrary issuer merely because its signing key is in a shared Microsoft key set. Inspect signing-key issuer restrictions and map identity using the intended tenant-stable identifiers, such as tid plus oid where that is the API contract. Compare identical local-looking subject/object values from two tenants and verify the tenant enrollment decision. General consent grants remain the Entra consent workflow.

## Discriminating verification

Use two synthetic tenant issuer-template/tid contexts with colliding local-looking principal fields. Compare approved tenant-stable identity mapping with mismatched issuer/key-issuer context before a protected local consumer.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Multi-tenant login can be intentional; a valid external tenant token is not a bypass without forbidden local access.

## Repair acceptance

Bind issuer/tenant/role admission to local policy and verify authorized onboarding and cross-tenant denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
