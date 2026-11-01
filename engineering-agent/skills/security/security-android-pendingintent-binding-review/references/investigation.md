# Investigation: PendingIntent mutability and delegated component/action authority

## Trace in the actual implementation

Follow which fields a lower-trust recipient can fill or change and whether the resulting operation executes with the creator authority.

## Implementation decisions

Inspect identity matching, requestCode, component, flags and reuse; extras alone do not generally distinguish token identity. Creator-side UPDATE_CURRENT differs from recipient fill-in authority. RemoteInput can legitimately require mutability. Determine which fields a real recipient can supply and which creator operation results; exported=false does not cancel an already-issued delegation.

## Discriminating verification

Use a local emulator with owned sender/receiver apps and an inert marker operation; compare intended invocation and one mutable-field substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A mutable PendingIntent can be required for a legitimate feature; demonstrate an unintended protected operation rather than the flag alone.

## Repair acceptance

Minimize delegated mutability and bind components/actions, verifying intended callbacks and rejected substitutions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/privacy-and-security/risks/pending-intent)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
