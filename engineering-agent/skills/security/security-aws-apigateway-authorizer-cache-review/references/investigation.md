# Investigation: API Gateway authorizer cache key and generated policy scope

## Trace in the actual implementation

Trace a cached authorization result across method/resource/tenant differences. For IAM policies inspect resource scope; for HTTP API simple responses inspect route-varying allow reuse.

## Implementation decisions

Branch first on REST API versus HTTP API and authorizer payload version. REST decisions can return scoped IAM policies; HTTP API v2 simple responses can return isAuthorized without any Resource policy. For each mode inspect identity sources, route-key inclusion, TTL and backend checks. Reusing an allow result matters only if a forbidden route/effect is then accepted.

## Discriminating verification

In an owned gateway fixture compare fresh and cached requests for two synthetic routes with different entitlements.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An authorizer cache hit is expected; establish a forbidden backend action or data result rather than only skipped authorizer logs.

## Repair acceptance

Align cache identity and mode-specific decision scope, including route-key identity when required; preserve authorized reuse and the declared revocation interval.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
