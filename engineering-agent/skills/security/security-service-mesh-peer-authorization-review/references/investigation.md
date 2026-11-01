# Investigation: Service-mesh mTLS peer identity and per-operation authorization

## Trace in the actual implementation

Follow verified workload identity into destination operation policy. mTLS transport authenticity does not alone authorize every service to invoke every method.

## Implementation decisions

mTLS authenticates a workload peer; it does not automatically authorize every HTTP route or tenant. Check whether plaintext bypass ports, excluded traffic or unenrolled workloads avoid the policy enforcement point. A legitimate authenticated service reaching an intentionally shared endpoint is expected; compare the same operation under a forbidden workload identity.

## Operational method

For Istio, evaluate applicable root/namespace/workload policy composition: DENY is considered before ALLOW, and the absence of an applicable ALLOW policy differs from an applicable ALLOW set whose rules do not match. Include other configured action modes and enforcement ports before concluding the request is permitted. Compare one authenticated allowed workload and one forbidden peer on the same operation; mTLS peer identity is only the input to this policy decision.

## Discriminating verification

Use an owned mesh fixture with two workloads and synthetic endpoints; compare allowed peer/action with another peer or bypass path.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An encrypted connection is not authorization proof; a connectivity failure before the proxy does not test the operation rule.

## Repair acceptance

Enforce peer/action policy across sidecar/gateway paths and retest intended traffic and denied peers.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://istio.io/latest/docs/concepts/security/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
