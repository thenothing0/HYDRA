# Investigation: Document share-link authority, recipient scope and revocation lifecycle

## Trace in the actual implementation

Trace who can issue or alter a share capability and whether it remains bound to the intended document, audience and operations after changes.

## Implementation decisions

Determine whether the link intentionally grants bearer access, requires a named recipient or is restricted to a tenant. Possession of an active bearer link is expected authorization under that model. Check permission changes, expiry and revocation at preview/export/download consumers; a cached page shell alone does not show continued private document access.

## Discriminating verification

Use two owned synthetic documents/users; compare intended share access with an unauthorized issuer, changed object or revoked link.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Anonymous bearer access can be the declared sharing feature; possession alone is not an authorization bypass.

## Repair acceptance

Bind issuance and share scope/lifetime to policy, retesting valid recipients, permission downgrade and revocation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
