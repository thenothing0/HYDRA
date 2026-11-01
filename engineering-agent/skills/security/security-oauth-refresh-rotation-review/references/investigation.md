# Investigation: Refresh-token family rotation, reuse response and atomicity

## Trace in the actual implementation

Track issuance, replacement and revocation as one transition. Determine whether reuse rejects only one request or invalidates the intended family and downstream sessions.

## Implementation decisions

Record the issuer policy for token-family reuse, allowed concurrency and any grace window. Do not assume every access token must be revoked on refresh reuse. Inspect atomic replacement and the exact descendants still usable after a detected replay, using synthetic local state rather than live token guessing.

## Operational method

Trace family ID, predecessor, replacement token and commit/delivery state. If rotation commits but the response is lost, a retry can be legitimate under an explicit grace/idempotency contract; distinguish it from two independently successful descendants exceeding policy. Use deterministic local interleaving and transport-loss simulation, then record which family members remain usable without treating every reuse event as proven theft.

## Discriminating verification

Replay one previously consumed synthetic refresh token and inspect family state; use deterministic local barriers for a race rather than live request bursts.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Two locally issued access tokens are not necessarily a defect if policy explicitly allows overlap; record actual reuse policy and validity.

## Repair acceptance

Implement atomic family transitions and the declared reuse response, then verify normal refresh and reuse handling.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9700)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
