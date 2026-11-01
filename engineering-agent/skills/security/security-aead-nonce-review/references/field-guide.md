# AEAD key, nonce and authenticated-context lifecycle — decision procedure

## Establish the boundary

Identify the actual primitive/library, key identity/rotation domain, nonce allocation and AAD contract. Trace persistence, restart, multi-writer and rollback states; nonce requirements depend on the chosen primitive and cannot be generalized from a name alone.

## Smallest decisive verification

Use fixed nonsecret fixture keys and an instrumented allocator/context verifier to show duplicate key/nonce pairs or accepted wrong context. Do not decrypt or manipulate real users' data. Separate an allocator/model trace from a complete production cryptographic attack.

## Reject or narrow unsupported conclusions

A random-looking nonce is not proof of uniqueness and equal nonces under different keys are not the same reuse claim. Tag bytes present in a record do not prove verification before plaintext use; fail-open consumers need their own trace.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Use the supported primitive contract with robust key/nonce lifecycle and authenticated context checks. Retest restart/concurrency/rotation and invalid-tag/context rejection before use, preserving legitimate stored-data migration needs.

## Evidence worksheet

primitive/library; stable key-identity model without key bytes; nonce generation/state; AAD/tag-use path; duplicate/context evidence; production reachability and valid decrypt control

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
