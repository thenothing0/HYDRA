# Investigation: Agreement between TLS identity, HTTP/2 authority and application tenant routing

## Trace in the actual implementation

Trace connection identity and per-request authority through the reverse proxy to the final tenant selection. Identify the authoritative check rather than assuming shared infrastructure implies shared access.

## Implementation decisions

HTTP/2 connection coalescing can legitimately send a different authority over an existing TLS connection when its trust requirements hold. Do not require literal SNI equality universally. The defect is wrong application/tenant authority or an explicitly violated routing policy, not every multi-authority connection.

## Discriminating verification

Use two owned virtual hosts and synthetic tenant responses on one isolated connection; compare intended authority and one permitted mismatch fixture.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A different error page, shared certificate or 421 response does not demonstrate another tenant content or action.

## Repair acceptance

Align authority handling and tenant checks, then verify correct routing, rejection and authorized connection reuse.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9113)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
