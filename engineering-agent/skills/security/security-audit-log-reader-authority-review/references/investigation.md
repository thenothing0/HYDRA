# Investigation: Audit query scope across partition expansion, cursor and export publication

## Trace in the actual implementation

Follow a caller query into effective log scope and serializer fields. Differentiate read access to security events from permission to read credentials/PII inside them.

## Implementation decisions

Evaluate reader scope, query filters, export jobs and fields independently from permission to perform the logged actions. Audit readers may intentionally see security-relevant cross-user metadata; establish which contents remain protected. A redacted UI does not prove raw export/search restrictions, and a permitted event count is not automatically a complete log disclosure.

## Operational method

Specialize in audit query/export scope carried across the UI, query DSL, cursor and async result link. Retain the immutable tenant/project scope attached to the reader capability and compare it with index/partition selection and field projection after query rewriting. Test a scoped synthetic search, a forged continuation/export context and the final redacted event payload. Ordinary one-object API access without audit query fan-out belongs in generic object/property review.

## Discriminating verification

Query synthetic audit events through a scoped reader capability, then alter the continuation/export query or partition while preserving the same visible filter. Inspect final event fields and artifact audience against the immutable scope.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An audit-event count or event type may be intentionally visible; require an actual field/object policy violation.

## Repair acceptance

Constrain reader scope and redact unnecessary sensitive fields, preserving authorized incident response and audit fidelity.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
