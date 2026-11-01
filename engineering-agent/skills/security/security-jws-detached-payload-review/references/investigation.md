# Investigation: Detached JWS payload bytes and signature-to-consumer agreement

## Trace in the actual implementation

Determine which exact bytes are authenticated and whether normalization/decoding makes the application act on different content than was verified.

## Implementation decisions

Separate ordinary detached JWS from unencoded-payload b64=false; the latter requires correct b64/crit processing. Signature validity and identical byte digests do not ensure equivalent JSON meaning if duplicate members have first/last parser differences. Bind accepted algorithm/key and parse the verified bytes consistently, rejecting ambiguous structures where the application contract requires uniqueness.

## Discriminating verification

Use local synthetic signed messages and harmless paired payloads differing at one transformation boundary; record verifier and consumer digests.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A valid signature on an unchanged intended payload is expected; a serialization rejection is not message substitution.

## Repair acceptance

Bind verification to the exact consumed representation and supported header policy, preserving legitimate detached payloads.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc7797)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
