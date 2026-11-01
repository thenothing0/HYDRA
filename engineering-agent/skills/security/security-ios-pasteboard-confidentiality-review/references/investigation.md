# Investigation: iOS pasteboard data classification and intended sharing lifetime

## Trace in the actual implementation

Determine whether protected app data is deliberately copied and which audience/lifetime policy applies, including local-only and expiration choices.

## Implementation decisions

Identify general versus named pasteboard, local-only/expiration settings and the recipient access behavior of the tested iOS version. A paste permission prompt or user-initiated paste changes the threat model. Show a synthetic classified value reachable by the specified unintended recipient; copying a deliberately shared value is expected functionality.

## Discriminating verification

Use owned test apps/device or a source fixture with synthetic values; compare intended user copy and an unexpected background copy path.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

User-requested copying is not automatically a leak, and a paste permission prompt alone does not prove another app obtained data.

## Repair acceptance

Limit unintended writes/sharing lifetime and verify legitimate copy/paste behavior under the supported OS.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.apple.com/documentation/uikit/uipasteboard)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
