# Investigation: gRPC reflection/schema visibility and its incremental confidentiality impact

## Trace in the actual implementation

Distinguish a discoverable descriptor from callable protected methods or genuinely confidential embedded options/comments. Resolve reflection authentication separately.

## Implementation decisions

Reflection may intentionally publish a public schema; classify actual descriptor content before severity. Authentication interceptors may apply differently to reflection and business RPCs. A reflected method is inventory until the real principal can call it or confidential descriptor content itself is shown.

## Discriminating verification

Compare the descriptor visible to an unauthenticated fixture client with intended public API documentation and a restricted method invocation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Reflection enabled or a method name exposed is not an authorization bypass; protected RPCs may still be correctly denied.

## Repair acceptance

Restrict truly sensitive schema publication if required and preserve intended tooling; retest descriptors and RPC authority independently.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://grpc.io/docs/guides/reflection/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
