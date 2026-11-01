# Investigation: Signed OAuth request object validation and outer-parameter precedence

## Trace in the actual implementation

Resolve signature trust and the authoritative source of client, redirect, scope and transaction fields when signed and unsigned parameters coexist.

## Implementation decisions

Select the exact JAR/profile and its signed-only requirements, outer client_id consistency and permitted outer-only parameters. Check issuer/audience/time, registered key and duplicate handling. Safe signed precedence can be correct; not every conflict requires rejection. Request objects, fetched request_uri objects, PAR and JARM are separate mechanisms, not interchangeable validation results.

## Discriminating verification

In an owned issuer fixture keep a valid request object constant and vary one unsigned conflicting field; observe which value drives authorization.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A signed JWT string is not proof of correct binding, but a rejected conflict is not a bypass either.

## Repair acceptance

Validate request-object context and authoritative parameter handling; verify legitimate signed requests and rejection or safe signed precedence for conflicting inputs under the selected profile.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9101)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
