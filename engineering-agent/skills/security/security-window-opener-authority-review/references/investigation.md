# Investigation: Navigation authority through real window.opener and named-window relationships

## Trace in the actual implementation

Establish how a lower-trust page retains an opener or reuses a named context, then which permitted cross-origin navigation operation reaches a trusted tab.

## Implementation decisions

Separate a newly opened blank target, an existing named window and a popup later navigating off origin. Confirm the opener survives the effective COOP group transition. Do not assume every target=_blank creates an opener, or that a popup blocker denial proves protection after an actual permitted popup opens.

## Discriminating verification

Use owned origins and visible benign navigation markers; compare the actual opener-linked path against an identical noopener or isolated-window control.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Modern implicit noopener, COOP separation or a null opener can invalidate a source-only concern; generic frameability is a different boundary.

## Repair acceptance

Remove unneeded opener authority and retest the actual popup flow, including required return messaging.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/API/Window/opener)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
