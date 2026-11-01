# Investigation: OIDC discovery metadata and issuer selection trust

## Trace in the actual implementation

Follow who selects issuer metadata and where its issuer, endpoints and keys become trusted. Keep owned discovery fixtures separate from arbitrary external fetch probing.

## Implementation decisions

Keep configured issuer identity stable across metadata caching and endpoint/key selection. Supporting several tenants is legitimate if each authorization transaction retains its issuer/client binding. A metadata fetch that merely redirects or fails is not a demonstrated login mix-up or server fetch authority violation.

## Operational method

Compare the configured expected issuer and returned iss using the selected OIDC exact issuer rules; do not normalize away a path, case-sensitive component or trailing slash as a convenience. Record discovery/key cache keys and the authorization transaction issuer. Two owned issuers with similar metadata URLs or colliding tenant cache entries distinguish metadata availability from a trust substitution.

## Discriminating verification

Use two owned issuers with distinct keys and subjects; compare the configured issuer with metadata or callback from the other issuer.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Fetching public metadata is normal; a discovered URL alone does not prove SSRF or login mix-up.

## Repair acceptance

Pin issuer/client context through discovery, caching and callback validation; verify legitimate tenant onboarding and cross-issuer rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://openid.net/specs/openid-connect-discovery-1_0.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
