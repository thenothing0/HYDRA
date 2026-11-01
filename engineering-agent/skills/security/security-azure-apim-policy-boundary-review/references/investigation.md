# Investigation: API Management policy transformations and backend identity authority

## Trace in the actual implementation

Trace identity after policy inheritance/condition branches and whether caller-controlled headers survive as trusted backend claims.

## Implementation decisions

Evaluate effective policy inheritance at global, product, API and operation levels, including base placement and policy expressions. Authentication at the gateway can be legitimate only if the backend trusts an unforgeable gateway path or validates identity independently. A rewritten caller header matters when the backend consumes it as authority, not when it is merely logged.

## Operational method

Collect the subscription used by the request and whether it is product-, API- or all-API-scoped before applying product-level policy. Build the effective inherited policy for that operation, including base placement, and inspect whether the backend accepts direct requests or caller-forgeable identity headers. Compare the same protected action through the real applicable gateway path and an owned direct-backend fixture; a policy merely present in another product is not an active check.

## Discriminating verification

Use an owned APIM/backend fixture; compare a legitimate request with one identity/header or route branch variation and inspect the backend principal.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A subscription key or successful gateway response does not prove backend authentication or cross-tenant access.

## Repair acceptance

Normalize identity at the trusted gateway boundary and enforce backend resource policy, retaining valid API products.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/api-management/api-management-policies)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
