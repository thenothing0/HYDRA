# Investigation: Reassigned account identifiers inheriting a previous principal authority

## Trace in the actual implementation

Trace a genuinely new principal through identifier allocation into old ACLs, memberships or ownership. Distinguish stable principal identity from a recycled display or login identifier; route residual deleted-record access to security-deleted-data-access-review.

## Implementation decisions

Distinguish an intentionally restored account from a genuinely new principal assigned a reused name, email or numeric ID. Follow immutable principal identity into ACLs, group memberships, ownership and cached entitlements. A recycled display name is harmless unless it selects old authority; compare a new principal with a legitimate restoration under the declared lifecycle policy.

## Discriminating verification

In a disposable identity fixture grant principal P1 a marker capability, retire P1, assign its reusable login label to distinct P2 and compare P2 with a fresh control and an explicitly restored P1.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An authorized restoration of the same principal or harmless display-name reuse is not cross-principal authority transfer; require an inherited protected capability under the product identity policy.

## Repair acceptance

Bind grants to immutable principals or identity generations, retire stale memberships/caches and verify safe identifier reuse alongside intended same-principal restoration.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
