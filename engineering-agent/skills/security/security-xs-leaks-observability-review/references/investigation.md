# Investigation: Cross-site state inference through a concrete browser observation channel

## Trace in the actual implementation

Separate protected state from noise and from values already public to the observer. Resolve the precise request and browser event visible without reading a cross-origin body.

## Implementation decisions

Randomize synthetic state order and record cache/service-worker warm-up and network variance. Distinguish an observable load/error event from reading its body. A consistent signal must identify protected state beyond public metadata; an automation-only timing or read channel is not available to an ordinary cross-origin page.

## Operational method

Define the observation channel, bounded sample budget and decision rule before collecting timings. Randomize two synthetic private states, retain a public/no-state control and reserve a separate confirmation sequence so a threshold is not selected on the same noise it claims to distinguish. Report uncertainty when the separation does not persist; no real-user state extraction is needed.

## Discriminating verification

Use two owned accounts/states and a bounded randomized local comparison with a public control; preserve raw observations and uncertainty rather than extracting real-user state.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A single faster response or a same-origin debugger read is not a cross-site inference capability; unstable separation remains inconclusive.

## Repair acceptance

Retest the same observation channel after isolation/cache/response changes and verify legitimate clients still receive their own data.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://xsleaks.dev/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
