# Investigation: Pushed Authorization Request binding to client, transaction and expiry

## Trace in the actual implementation

Trace who creates and redeems a request_uri, which client/parameters it binds, and how replay or expiry is enforced at authorization.

## Implementation decisions

Check the same request_uri at creation and redemption, including authenticated client binding and lifetime. A request_uri is not an arbitrary resource URL the client should fetch. Treat repeated authorization attempts according to issuer policy/specification rather than assuming every second use is forbidden.

## Operational method

Distinguish public client identification from confidential client authentication at PAR; do not require a secret for every client. Retain the authenticated/identified client, persisted parameters and request_uri at redemption. Apply the applicable one-use expectation and explicitly supported browser-reload exception rather than an unrestricted reuse policy. Compare correct client redemption, a different client and a permitted reload under the actual issuer profile.

## Discriminating verification

Use two owned clients in an issuer fixture; compare the rightful redemption with a client-swapped or expired reference and inspect resulting authorization state.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A random request_uri error or a 403 at PAR is not an authorization bypass; a nested redirect string alone is not a redirect consumer.

## Repair acceptance

Bind the pushed request to the authenticated client and lifetime, then retest intended authorization and substitution denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9126)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
