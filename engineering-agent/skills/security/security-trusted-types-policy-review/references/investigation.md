# Investigation: Trusted Types policy creation and trust at DOM injection sinks

## Trace in the actual implementation

Trace an attacker-controlled value through createHTML/createScriptURL or the default policy into the protected sink. Determine whether the factory sanitizes the actual context or merely wraps input.

## Implementation decisions

Identify which factory and output type reaches the sink: TrustedHTML is not TrustedScriptURL. An unsafe default policy can convert raw strings and must be traced separately from named factories. Policy-name allowlisting controls factory creation; it does not certify that the approved factory sanitizes its input.

## Operational method

Record the sink type, assignment result/exception, selected default or named factory and resulting DOM or script URL. A raw string TypeError is different from a default policy transforming the same input into an accepted typed value. Exercise the real factory on legitimate content and an inert untrusted marker; policy creation or a TrustedHTML label alone supplies no sanitization oracle.

## Discriminating verification

Use an owned DOM fixture with a benign execution marker and legitimate rich content; compare raw strings with values produced by the real policy factory.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A TrustedHTML object is not proof of sanitization. An unsupported browser or unenforced policy cannot prove the protected configuration failed.

## Repair acceptance

Constrain policy creation and repair the factory/consumer, then verify rejected untrusted markup and preserved intended rendering.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
