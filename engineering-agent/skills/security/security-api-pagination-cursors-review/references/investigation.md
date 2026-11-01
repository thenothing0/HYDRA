# Investigation: Pagination cursor binding across account, tenant and filters

## Trace in the actual implementation

Follow the continuation token into the resumed query. Check whether it preserves or overrides tenant, sort/filter and current entitlement rather than trusting issuance context forever.

## Implementation decisions

Check whether the cursor carries authority or only a position; a signed position can still be safely re-authorized. Keep initial and resumed query filters visible. Sort-key changes, deleted rows and expiry can change a page without implying cross-tenant access; require an attributed unauthorized synthetic record.

## Discriminating verification

Compare a legitimate next page with the same cursor under another owned actor or changed filter; inspect returned synthetic objects.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An opaque or unsigned cursor is not a flaw if the resumed query re-enforces policy; an empty page proves no data access.

## Repair acceptance

Bind or revalidate cursor context and current authorization, preserving normal pagination and stable results.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
