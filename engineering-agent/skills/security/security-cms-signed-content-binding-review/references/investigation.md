# Investigation: CMS signed object, signer purpose and consumed-content binding

## Trace in the actual implementation

Trace the verified signer and signed bytes to the exact document/action consumed, including detached content and duplicate/ambiguous structures.

## Implementation decisions

Resolve attached versus detached content, signed attributes, signer certificate purpose and the exact object the consumer uses. A cryptographically valid signer may not be trusted for this operation. Unsigned outer metadata or an alternate embedded object must not replace verified content; compare intended signed data and a harmless alternate object in an offline fixture.

## Operational method

Select the CMS signedAttrs branch explicitly. For id-data, signedAttrs may be absent; verification then covers the content-octet path defined by the profile, so do not reject that valid form merely for lacking attributes. When signedAttrs is present, validate required content-type/message-digest attributes, their agreement with selected content and the specified signed-attribute encoding; non-id-data requires signedAttrs. Retain the actual verifier-selected signer/content and consume that verified result, not an unsigned outer alternative. An embedded certificate is not automatically an authorized signer. Compare valid id-data without attributes with an attributed-content mismatch and a wrong-purpose signer offline.

## Discriminating verification

Use an isolated fixture with owned certificates and synthetic documents; compare rightful signer/content and a wrong-purpose or mismatched content object.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A mathematically valid signature is not application signer authorization; a displayed certificate subject is not proof of trust.

## Repair acceptance

Bind accepted signer purpose and content representation to the consumer and verify valid signed workflows.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc5652)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
