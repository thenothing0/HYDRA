# Investigation: Cloud Storage effective publication across IAM, ACL and bucket modes

## Trace in the actual implementation

Resolve the effective access path for one principal/object and distinguish object retrieval, listing and modification under the configured bucket mode.

## Implementation decisions

Branch on uniform bucket-level access: enabled UBLA disables ACL grants. With UBLA disabled, applicable IAM and ACL grants act in parallel; checking only one can miss an allow. Resolve inherited public-access prevention (PAP): it blocks allUsers/allAuthenticatedUsers grants but does not revoke signed URLs authorized through their signer. Such a URL succeeding is not a PAP bypass; review issuer entitlement separately. A stale public ACL alone proves no current exposure. Compare direct anonymous access, entitled identity access and any separately authorized signed capability.

## Discriminating verification

Use owned public/private synthetic objects and compare anonymous and intended principal operations at known paths.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A public bucket label or metadata alone is not disclosure of a confidential object; disabled ACL paths must not be treated as effective grants.

## Repair acceptance

Align publication mode and effective grants, verifying intentional public content and private-object denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/storage/docs/access-control)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
