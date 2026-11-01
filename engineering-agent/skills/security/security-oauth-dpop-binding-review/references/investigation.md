# Investigation: DPoP proof validation and token-to-key binding

## Trace in the actual implementation

Trace proof key ownership, htm/htu binding and access-token hash to the protected operation. Identify where proofs can be replayed or accepted for another token/resource.

## Implementation decisions

Compare token cnf.jkt with the canonical public-JWK thumbprint of the verified proof key. Check proof typ, allowed asymmetric algorithm, htm, htu, time and jti replay policy. htu excludes query and fragment. Resource requests require the contextual access-token hash ath; token-endpoint proofs differ. A valid nonce challenge followed by a fresh proof is not replay acceptance.

## Discriminating verification

Use owned synthetic tokens/keys on a local resource; compare the rightful request with a mismatched proof key or recorded single replay.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A valid proof signature does not establish token binding; failure caused only by a malformed request cannot show replay protection works.

## Repair acceptance

Enforce proof context and replay policy, then verify authorized proof renewal and controlled mismatches.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9449)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
