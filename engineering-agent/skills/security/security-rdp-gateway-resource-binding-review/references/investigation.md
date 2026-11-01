# Investigation: RDP gateway identity, resource authorization and session lifecycle

## Trace in the actual implementation

Trace authenticated identity and approved target into the actual remote-session connection, including aliases and reconnect state.

## Implementation decisions

Distinguish gateway connection authorization, resource authorization and target host login. Passing one gateway policy does not establish access to every internal host or desktop session. Follow user/group conditions, selected resource and any session reconnection policy using supplied configuration or a lab, and preserve target authentication as a separate necessary edge.

## Discriminating verification

Use owned lab targets or configuration proof with synthetic identities; compare an entitled target and one forbidden target/resource alias.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Gateway login or target discovery is not a desktop session; denial before connection is a meaningful control.

## Repair acceptance

Bind connection/resource policy to normalized targets and verify permitted reconnect and revocation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-gateway-role)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
