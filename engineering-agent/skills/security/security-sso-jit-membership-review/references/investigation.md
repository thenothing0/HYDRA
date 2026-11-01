# Investigation: SSO just-in-time organization and role assignment

## Trace in the actual implementation

Follow issuer-controlled and user-controlled attributes into organization selection and role grants. Determine which IdPs are trusted for which tenant authority.

## Implementation decisions

An email-domain string is not necessarily verified domain control. Establish which issuer is trusted to assert which organization and role. Existing-user account linking and new-user JIT admission are distinct transitions; accepting a new low-privilege user does not prove administrative membership or existing-account takeover.

## Discriminating verification

Use owned tenants/IdPs with a controlled domain or role collision and inspect resulting membership/capabilities server-side.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Creating an ordinary account through an allowed IdP is expected; a domain string without a granted membership is not tenant takeover.

## Repair acceptance

Constrain issuer-to-tenant/role mappings and retest authorized JIT entry and unauthorized membership assignment.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
