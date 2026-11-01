# Investigation: SAML metadata update provenance and effective signing-key trust

## Trace in the actual implementation

Determine who can replace an entity descriptor or endpoint and how new signing keys become trusted. Separate metadata authentication from assertion validation.

## Implementation decisions

Metadata can be authenticated by an approved signed distribution or another deliberate pinned trust channel; unsigned is not universally unsafe. Bind entityID and rollover keys to that channel. Distinguish an administrator-approved new IdP from an attacker-controlled metadata source replacing an existing trusted entity.

## Operational method

For aggregated metadata, retain the exact signed descriptor scope and selected entityID entry, not merely a successful signature somewhere in the document. Verify the entity entry and rollover keys consumed by the SP derive from the authenticated scope/distribution policy. A locally altered unsigned sibling entry is a useful negative control; a trusted administrator intentionally approving a different IdP is privileged setup.

## Discriminating verification

Use an owned IdP/SP fixture with a legitimate rollover and an unauthorized metadata source/entity substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An old certificate remaining during an approved rollover window is not automatically a trust bypass; record the actual acceptance policy.

## Repair acceptance

Authenticate metadata updates and bind them to the intended entity, preserving controlled rollover and failure recovery.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
