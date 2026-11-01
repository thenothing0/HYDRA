# Investigation: Custom-domain ownership proof and tenant routing lifecycle

## Trace in the actual implementation

Trace who controls the verification token and whether old proof can claim a different tenant/domain or survive intended ownership removal.

## Implementation decisions

Distinguish hostname normalization, current proof ownership and the tenant allowed to claim it. Old verification tokens may be invalidated or remain valid by declared policy. A dangling DNS target is not proof that a provider will accept a new claim; use only an owned domain/fixture for that transition.

## Operational method

Record which DNS/HTTP proof method was accepted and how alternate methods interact. An HTTP challenge hosted by the same unverified SaaS tenant can make ownership proof circular; locate the independent domain-controlled endpoint before trusting it. Compare an owned domain under each supported method, stale proof and reassignment, without claiming another party hostname or registering its dangling resource.

## Discriminating verification

Use only owned domains or a local resolver fixture; compare correct proof with another owned tenant challenge and a stale ownership transition.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A DNS CNAME or validation error does not prove claimability; never claim an unowned production domain to strengthen the report.

## Repair acceptance

Bind proof to normalized domain, tenant and current transaction, then verify renewal/removal and rightful onboarding.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
