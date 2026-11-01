# Investigation: React Native JavaScript-to-native module capability boundaries

## Trace in the actual implementation

Determine whether lower-trust JS/content can reach privileged native methods and choose resources/actions beyond its authorized feature.

## Implementation decisions

Define whether JavaScript is trusted bundled code or lower-trust remotely supplied content. A native method exposed to the trusted application runtime is not automatically a web-origin bridge. Trace the actual entry from WebView/messages/updates into module arguments, native permissions and object checks before claiming another origin can invoke it.

## Operational method

Resolve legacy bridge versus New Architecture/TurboModule registration, the actual exported native method and per-platform argument conversion. Find the lower-trust entry into that method before treating bundled application JS as an attacker. Compare a legitimate native invocation with a malformed/foreign-resource value at the real conversion boundary using an owned app fixture; a generic mock bridge cannot prove installed module exposure.

## Discriminating verification

Use an owned app fixture with an inert native operation and synthetic JS input; compare intended calls and a forbidden resource selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A powerful native module exposed to fully trusted application JS is not itself a defect; establish a lower-trust caller path.

## Repair acceptance

Constrain module arguments and capabilities at the native boundary and retest intended application use.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://reactnative.dev/docs/native-platform)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
