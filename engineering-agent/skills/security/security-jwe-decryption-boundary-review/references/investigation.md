# Investigation: JWE key/algorithm/context selection and decryption error handling

## Trace in the actual implementation

Trace untrusted protected/unprotected header choices into key/algorithm use and then into a purpose-specific validated payload.

## Implementation decisions

Bind key selection and allowed alg/enc values to the recipient/context rather than trusting header choices. Successful decryption authenticates the ciphertext under a key, not necessarily its sender or tenant. Inspect any nested signature and application claims separately; differing local error text alone does not demonstrate an exploitable remote oracle.

## Discriminating verification

Use local synthetic keys/ciphertexts and bounded valid/invalid cases; compare intended context with a wrong purpose/key/algorithm path without recovering production plaintext.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Different error messages alone do not prove a practical decryption oracle; decrypted bytes accepted for another purpose need separate evidence.

## Repair acceptance

Constrain algorithms/keys/context and uniform failure handling, retesting valid messages and prohibited combinations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc7516)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
