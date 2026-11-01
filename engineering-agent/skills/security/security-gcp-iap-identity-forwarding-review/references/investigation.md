# Investigation: Identity-Aware Proxy assertion validation and origin reachability

## Trace in the actual implementation

Trace a verified IAP assertion into application identity, including issuer/audience and whether direct origin requests can supply equivalent unverified headers.

## Implementation decisions

Check the signed IAP assertion and its exact protected-resource audience; email/identity headers alone may be forgeable on a direct backend path. Determine whether network/ingress restrictions actually prevent that path before declaring bypass. A legitimate request through IAP is a positive control, not proof that all origin routes validate the assertion.

## Discriminating verification

Use an owned proxy/backend fixture; compare intended IAP request and direct synthetic identity-header input.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An email header name or unreachable origin is not authentication bypass; verify a protected synthetic response under the forged identity.

## Repair acceptance

Validate assertions and origin ingress consistently, preserving authorized proxy traffic and rejecting direct impersonation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/iap/docs/signed-headers-howto)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
