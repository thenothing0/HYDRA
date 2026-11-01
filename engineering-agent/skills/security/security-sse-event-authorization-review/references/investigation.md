# Investigation: Server-Sent Events stream identity and per-event resource filtering

## Trace in the actual implementation

Follow requester identity into channel/cursor selection and each emitted object. Check replay/resume without replacing current authorization with a cursor capability by accident.

## Implementation decisions

Last-Event-ID can be a resume position rather than a bearer credential. Reapply the current actor/resource filter to replayed events. Distinguish broker events already authorized and buffered before revocation from new events, and do not equate HTTP stream establishment with delivery of protected data.

## Discriminating verification

Use two owned streams and synthetic events; compare normal subscribe/resume with a foreign cursor/channel and a revoked membership.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A kept-alive response or guessed channel name is not cross-user event exposure; prove an unauthorized synthetic event is delivered.

## Repair acceptance

Bind stream/cursor access to current policy and verify entitled resume plus restricted event exclusion.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://html.spec.whatwg.org/multipage/server-sent-events.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
