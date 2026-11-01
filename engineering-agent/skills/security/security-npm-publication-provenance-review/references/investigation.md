# Investigation: npm trusted-publisher identity and alternate package publication paths

## Trace in the actual implementation

Trace which repository/workflow/environment can publish the package and whether provenance corresponds to the exact consumed artifact rather than a different run.

## Implementation decisions

Separate publisher authentication, package ownership, artifact integrity and provenance subject identity. An attestation can accurately describe a malicious but authorized build; it does not replace source trust. Bind the actual registry tarball digest to the expected repository/workflow identity, and do not publish a test package or install untrusted lifecycle scripts for verification.

## Operational method

Inspect the package registered trusted-publisher identity: CI provider, repository/project, workflow and any configured environment. Bind that identity to the OIDC exchange and actual package/version publication; provenance subject digest matching is a separate check. Record remaining legacy automation tokens or publish paths that bypass the intended publisher restriction. Use supplied registry/publisher records and offline artifacts; do not publish a package or infer source review from an accurate attestation.

## Discriminating verification

Compare the package registered trusted-publisher CI identity with a mismatched repository/workflow/environment and an alternate legacy publishing credential path using supplied configuration and offline artifacts. Do not publish or install a package.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A provenance badge or package metadata field alone is not verified release trust; do not publish a conflicting public package to test it.

## Repair acceptance

Bind publication to intended workflow identity and verify artifact provenance at the release consumer.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.npmjs.com/generating-provenance-statements)
- [Additional implementation reference](https://docs.npmjs.com/trusted-publishers/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
