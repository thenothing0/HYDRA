# Investigation: Azure Blob container/object publication and private access paths

## Trace in the actual implementation

Separate intended public blob retrieval from container listing, writes and private data delivery. Evaluate SAS and identity-based access as distinct authority paths.

## Implementation decisions

Resolve account-level public-access restrictions and container-level settings alongside any CDN/static-website path. Blob versus container anonymous access differ in listing behavior. An unguessable name is not authorization, but intentionally public assets are not private data exposure. Test one owned synthetic object and inspect effective policy rather than enumerating unknown object names.

## Discriminating verification

Use owned public and private synthetic blobs; compare anonymous retrieval/listing with intended authenticated access.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A public marketing blob or guessed URL is not sensitive exposure; existence and intended confidentiality must be established.

## Repair acceptance

Align account/container publication and issuing application policy, verifying public assets and private-data denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
