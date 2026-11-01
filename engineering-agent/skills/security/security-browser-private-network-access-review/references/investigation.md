# Investigation: Browser-mediated requests from a public page into an owned private-network service

## Trace in the actual implementation

Follow the browser network-permission and CORS boundaries separately from destination reachability. Determine whether the attacker can read a result or trigger a protected effect.

## Implementation decisions

Determine the deployed browser generation: historical PNA preflight and newer LNA permission behavior are not interchangeable. Record secure context, initiator origin, resolved address space and permission state. An explicit user-granted local-network permission is not a bypass. A loopback fixture is not automatically representative of a public-to-private transition; preserve the actual prerequisites.

## Operational method

Record engine build, enabled feature/enterprise policy, permission state and whether the profile grant was reset before the comparison. The same version may have different rollout or policy settings. Retain initiator and resolved destination address spaces with the actual request count. A granted-permission success and denied-permission absence are different expected branches; a loopback-only setup must not stand in for an untested public-origin transition.

## Discriminating verification

Use only an owned isolated service with an inert marker and compare permission-denied and intended-origin controls; never enumerate a victim network.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An attempted fetch, private IP string or server-side fetch result is not a browser private-network bypass.

## Repair acceptance

Constrain origin/authorization on the internal service and verify the recorded browser flow after repair.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.chrome.com/blog/local-network-access)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
