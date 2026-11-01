# Investigation: Device Authorization Grant account/device transaction binding

## Trace in the actual implementation

Separate the device transaction, user confirmation and polling client. Determine which account and audience the final token represents, including user-visible confirmation.

## Implementation decisions

Distinguish device_code, human user_code and the polling client; they have different audiences. A user confirmation must be tied to the intended device transaction, but cross-device confirmation is normal. Use expiry/polling errors as protocol observations, not evidence of account authentication unless a token is actually issued.

## Operational method

Identify issuer, client_id, device_code and the approved user transaction in the polling state. Public clients are identified differently from confidential clients that authenticate. Separate authorization_pending, access_denied and expired_token states from successful token issuance; a user_code displayed on another device is normal. Compare rightful polling with a client/transaction mismatch in an owned issuer fixture, without asking a real user to approve an attacker transaction.

## Discriminating verification

In an owned issuer fixture confirm one device transaction, then compare another client/device transaction and expired/reused codes without guessing user codes.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A deliberately portable user code is not a flaw by itself; no token issuance or wrong-account binding means the strong claim is unproved.

## Repair acceptance

Bind the approved transaction, client and account; retest legitimate pairing, expiry and unauthorized transaction substitution.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc8628)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
