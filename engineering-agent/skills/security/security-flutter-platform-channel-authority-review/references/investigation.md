# Investigation: Flutter platform-channel message identity and native operation binding

## Trace in the actual implementation

Trace an externally influenced Dart/channel argument into the native consumer and its resource/operation checks.

## Implementation decisions

Platform channels carry application-runtime messages and do not inherently authenticate a web origin. Establish the lower-trust Dart/plugin/embedder entry point and the native handler identity first. A handler accepting arbitrary paths is relevant only if an untrusted actor reaches it outside intended app authority; inspect each platform implementation separately.

## Operational method

Retain channel name, codec, native registration and owning engine/binary messenger; for EventChannel include listen/cancel ownership and subscription lifetime. Follow the actual lower-trust Dart/plugin/embedder entry into native argument conversion and protected operation. Compare an intended request and a stale/wrong-engine or foreign-resource context in the supplied app path. An arbitrary handler stub establishes no installed channel reachability.

## Discriminating verification

Use an owned app/local channel stub with synthetic values; compare the allowed method/resource and a reachable unauthorized selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A channel method name or plugin permission is not an attacker entrypoint without a source path.

## Repair acceptance

Validate native operation authority and channel lifecycle, preserving legitimate plugin features and rejecting untrusted selections.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.flutter.dev/platform-integration/platform-channels)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
