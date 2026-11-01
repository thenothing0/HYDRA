# Investigation: Preflight caching and credentialed CORS across an actual policy transition

## Trace in the actual implementation

Determine which decision is cached by the browser and which remains enforced on the actual response/server operation. Track method/header/origin and profile identity.

## Implementation decisions

Classify browser-readable protected data separately from a cookie-authenticated mutation. The browser preflight cache differs from an HTTP response cache; simple requests need no preflight. Actual credentials and SameSite admission still matter. Cached preflight permission does not remove response CORS checks; if only a PUT commits, investigate server authorization/CSRF and compare fresh, cached and expired states.

## Discriminating verification

In an owned fixture compare fresh and previously preflighted contexts before and after narrowing permission; observe actual browser reads and committed synthetic effects.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A cached successful OPTIONS response does not alone expose a credentialed body or authorize a state change.

## Repair acceptance

Enforce the actual request/response boundary and retest both cached and fresh browser paths.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://fetch.spec.whatwg.org/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
