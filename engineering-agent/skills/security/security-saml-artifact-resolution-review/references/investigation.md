# Investigation: SAML artifact resolution binding to issuer, recipient and transaction

## Trace in the actual implementation

Trace the opaque artifact through the trusted back channel to the assertion actually consumed, including requester identity and InResponseTo/recipient checks.

## Implementation decisions

Keep artifact source, authenticated resolving SP and the returned assertion transaction linked. Artifact possession alone need not authorize an unrelated resolver. Inspect the consumed assertion recipient/correlation after resolution; successful back-channel TLS by itself does not prove the correct assertion was selected.

## Operational method

Parse the supported artifact type and its source/index under the actual SAML binding before choosing the resolver. Bind the artifact, authenticated resolving SP and returned assertion to the same transaction/recipient. Retain one-use/expiry state separately from back-channel TLS. An opaque handle lookup stub cannot establish SAML source selection unless it preserves the actual artifact and resolver identity rules.

## Discriminating verification

Use two owned SP transactions in a local federation fixture and compare rightful artifact resolution with swapped requester or replay.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Opaque artifact syntax does not prove confidentiality or correct binding; failure at transport authentication must not be called assertion replay protection.

## Repair acceptance

Bind artifact, SP and transaction and enforce intended reuse semantics; retest normal resolution and substitution denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
