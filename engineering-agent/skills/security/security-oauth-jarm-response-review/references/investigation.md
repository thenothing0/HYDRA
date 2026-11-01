# Investigation: JWT-secured authorization response trust and transaction binding

## Trace in the actual implementation

Follow the signed authorization response through validation to code exchange and final session. Preserve the difference between authentic issuer data and correct client/transaction binding.

## Implementation decisions

Separate response signature/encryption processing from transaction state and authorization-code exchange. Verify issuer/audience and registered response mode/algorithms in context. A valid response for another owned client is a useful mismatch control; a malformed unsigned object rejected before parsing tests no transaction-binding property.

## Operational method

Bind the verified response to one initiating browser transaction and consume its state according to the client replay policy. Keep code exchange tied to the expected issuer/client, redirect URI and PKCE transaction as applicable. Compare two concurrent transactions for the same client, not only different audiences. A valid signed response delivered to the wrong local transaction must not silently complete that other session.

## Discriminating verification

Use an owned client/issuer fixture and compare a valid response with a response for another owned client or expired transaction.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Correct JWT signature verification alone is not a full callback check; an error without a minted session rejects the attack hypothesis.

## Repair acceptance

Bind issuer, audience and transaction before exchange/session creation; retest valid, wrong-client and replay paths.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://openid.net/specs/oauth-v2-jarm-final.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
