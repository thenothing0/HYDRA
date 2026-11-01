# Investigation: Content-Type and body-decoder disagreement at security checks

## Trace in the actual implementation

Follow whether authentication, CSRF or schema checks inspect the same representation later consumed by the handler. Include content-type parameters and fallback decoders only when reachable.

## Implementation decisions

Check accepted charset/structured-suffix and fallback decoding using the installed framework. A simple content type accepted as JSON can matter to CSRF only if the real authentication and state-change path allows it. Separate decoder disagreement, authorization failure and same-origin response-read claims.

## Discriminating verification

Use two harmless representations of one owned operation and compare the authorized baseline with one policy-relevant decoder variation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Merely accepting JSON and form data is not a flaw; a decoder error or unchanged denial does not show a security boundary crossed.

## Repair acceptance

Make accepted formats explicit and apply the security check to the consumed representation; retest intended formats and ambiguous rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9110)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
