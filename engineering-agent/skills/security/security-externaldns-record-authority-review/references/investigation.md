# Investigation: ExternalDNS source-object control and DNS zone delegation

## Trace in the actual implementation

Follow a resource annotation/hostname into DNS changes under the controller identity. Determine tenant/zone boundaries and collision/takeover behavior.

## Implementation decisions

Resolve controller sources, domain filters, namespace/label selectors and provider credentials. A TXT ownership record coordinates controllers; it is not universally an authorization boundary against a cluster actor who controls admitted sources. Show which owned zone/record the restricted source can influence and distinguish provider-side IAM denial from a controller filtering decision.

## Discriminating verification

Use a local provider stub or owned test zone; compare a permitted record with an out-of-tenant name requested by a lower-trust resource writer.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A requested hostname or dry-run log is not an actual DNS change; never claim or overwrite unrelated domains.

## Repair acceptance

Bind source writers to permitted zones/names and verify conflict handling, deletion and legitimate reconciliation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://kubernetes-sigs.github.io/external-dns/latest/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
