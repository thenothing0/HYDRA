# Investigation: Product-specific HSM export ceremony, quorum and recipient security domain

## Trace in the actual implementation

Determine who chooses the wrapping key and whether a protected non-export use can be converted into export under a caller-controlled key.

## Implementation decisions

Distinguish plaintext export, wrapping and an authorized backup/replication channel. Wrapping under an attacker-controlled importable key can have different consequences from wrapping to an approved recipient, but requires actual object/mechanism permission. Inspect wrap templates, trusted-key requirements and destination control using synthetic software-token keys; no production key extraction is needed.

## Operational method

Specialize in the supplied product export/backup ceremony, not generic PKCS#11 wrapping. Retain partition/security-domain identity, export mode, quorum/approval evidence, recipient wrapping-key provenance and the importing destination constraints. Compare an approved synthetic-key ceremony with a missing approval or wrong recipient in vendor-supported test evidence. Software-token wrap behavior cannot certify a vendor backup mechanism; absent product artifacts leaves that ceremony unassessed.

## Discriminating verification

Use vendor-supported supplied evidence or a test-only ceremony for a synthetic key. Compare approved quorum/recipient/security domain with a missing approval or wrong destination; never infer hardware export policy from a generic software token.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A supported backup/export API is not a defect if restricted to the approved role and destination policy.

## Repair acceptance

Bind export/wrapping approval to key purpose and destination trust, preserving legitimate recovery.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
