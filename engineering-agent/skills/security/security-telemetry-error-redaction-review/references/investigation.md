# Investigation: Secret redaction at actual error/telemetry serialization boundaries

## Trace in the actual implementation

Follow a synthetic sensitive value through nested errors, URLs, headers and serializer fallbacks into the transmitted/retained event.

## Implementation decisions

Find the actual serialization boundary for exception chains, structured attributes, attachments and fallback loggers. A redacted top-level message can coexist with a raw cause or breadcrumb. Use synthetic canaries with secret-like structure, confirm collector/export output and retain only the minimum redacted evidence; do not treat a regex match as proof of a real credential.

## Discriminating verification

Use local telemetry stubs with synthetic fixtures in distinct field encodings; compare redacted expected fields and one nested/fallback path.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A redaction function existing in source is not proof it handles the emitted shape; an unrelated private tester log is not a target disclosure.

## Repair acceptance

Redact before transmission with structured field policy and verify normal debugging fields remain useful.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://opentelemetry.io/docs/security/handling-sensitive-data/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
