# Investigation: App Transport Security exceptions and actual TLS client validation

## Trace in the actual implementation

Resolve which request uses which TLS policy and whether custom challenge handling changes peer validation independently of ATS.

## Implementation decisions

ATS exceptions and custom trust callbacks affect different parts of the effective connection policy. Resolve URLSession/web/native library behavior and the production plist. An exception allowing HTTP is not proof a sensitive request uses it, while a custom accept-all trust callback may matter even with apparently strict plist settings.

## Discriminating verification

Use an owned endpoint and synthetic data on a test device/simulator; compare valid TLS and a mismatched test peer.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An ATS exception alone is not a demonstrated secret leak or accepted invalid peer; non-applicable network stacks require separate evidence.

## Repair acceptance

Apply the intended peer/transport policy in the actual client and verify legitimate network operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
