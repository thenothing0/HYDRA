# Investigation: Idempotency key binding to actor, tenant and request meaning

## Trace in the actual implementation

Determine whether a caller-chosen key can select another actor response or suppress/replace a different operation. Distinguish retries from unrelated requests.

## Implementation decisions

Model first use, rightful retry, changed body, changed tenant and expiry separately. Some APIs intentionally reject a reused key with different parameters. Returning another tenant response, suppressing its action or replaying its effect are different outcomes; do not infer all three from a key collision.

## Discriminating verification

Use two owned tenants and synthetic reversible operations sharing one key; compare the rightful retry with a changed payload or tenant.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A duplicate correctly returning the same caller result is expected; shared key syntax does not prove cross-user cache reuse.

## Repair acceptance

Bind cached outcomes to security context and operation meaning, preserving safe retries and documented conflict responses.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
