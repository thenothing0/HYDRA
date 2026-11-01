# Investigation: iOS App Group container authority across app and extension identities

## Trace in the actual implementation

Trace which signed components can reach shared data and whether lower-trust extension input changes another component protected state.

## Implementation decisions

Use signed entitlements of each app/extension and the actual shared container identifier. App Group sharing is intentional among authorized members; the boundary may instead be account switching or an untrusted extension capability. A directory name seen in source is not proof of installed access or cross-team container entitlement.

## Operational method

Separate App Group file-container access from Keychain access-group entitlements; sharing one does not imply the other. Retain signed entitlements, the actual container API/path, file protection class and extension/application identity. Compare a synthetic account switch or extension read against the declared audience/lifecycle. Merely showing that authorized group members share a container is expected behavior, not cross-team privilege.

## Discriminating verification

Use owned signed test targets and synthetic shared data; compare intended extension exchange with an out-of-policy action/resource selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A shared group identifier is not proof that an unrelated app can access it; entitlement enforcement remains essential.

## Repair acceptance

Constrain shared data and per-operation authority within entitled components, preserving legitimate extensions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.apple.com/documentation/xcode/configuring-app-groups)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
