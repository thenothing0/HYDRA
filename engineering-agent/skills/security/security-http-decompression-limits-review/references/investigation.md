# Investigation: Admission limits on compressed request bodies before expensive decoding

## Trace in the actual implementation

Find where each size/cost limit applies relative to decompression and parsing. Track nested encoding and abort propagation without constructing production exhaustion traffic.

## Implementation decisions

Track a cumulative budget across compressed layers and streamed parser reads; limiting each chunk separately may miss the aggregate. Check whether cancellation stops upstream decoding and releases partial buffers. Rejecting the full body after an authoritative state change is a different problem from admission before parsing.

## Operational method

For every decoder stage record compressed bytes admitted, cumulative decoded bytes, buffered allocation and cancellation completion. A size error after buffering a large body is not admission before allocation. Use tiny local thresholds and a bounded input crossing one limit at a time; verify the upstream reader stops and partial buffers/state are released, while the legitimate bounded body still reaches its parser.

## Discriminating verification

Use tiny bounded local fixtures that cross configured decoded limits while staying within safe resource budgets; verify timely rejection and cleanup.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Compression support or a high theoretical ratio is not a live denial-of-service demonstration; a parser rejecting before allocation may already protect the path.

## Repair acceptance

Enforce cumulative decoded limits and cancellation, then check normal compressed input and bounded over-limit rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9110)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
