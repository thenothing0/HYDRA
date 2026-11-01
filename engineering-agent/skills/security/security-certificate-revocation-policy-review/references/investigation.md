# Investigation: Application certificate revocation checking and declared failure policy

## Trace in the actual implementation

Trace whether the application checks revocation for the relevant trust decision and how revoked, unknown and unreachable outcomes differ.

## Implementation decisions

Determine the relying application policy for OCSP/CRL, stapling, cached status, freshness and network failure. Soft fail may be an explicit availability choice; a connection succeeding during lookup failure is not universally a bypass. Compare good, revoked and unavailable-status fixtures against the declared policy without contacting or revoking production certificates.

## Operational method

Choose OCSP or CRL as actually consumed. For OCSP retain responder signer authorization, certificate/issuer identifier, status and thisUpdate/nextUpdate freshness under policy; for CRLs retain issuer, scope and update validity. Distinguish authenticated revoked/good results from unavailable or stale status and record the client failure rule. A tri-state fake responder establishes policy branching only, not verification of a real status artifact.

## Discriminating verification

Use an owned lab CA/client and synthetic certificates with controlled revocation responders; compare valid, revoked and unavailable states.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A missing network lookup can be explained by cache/stapling or platform policy; do not infer acceptance without the actual protected connection/operation.

## Repair acceptance

Enforce the declared revocation/failure contract and verify legitimate connectivity, revoked rejection and recovery.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc5280)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
