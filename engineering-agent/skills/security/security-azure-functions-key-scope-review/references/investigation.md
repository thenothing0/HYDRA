# Investigation: Azure Functions host/function keys and application action authority

## Trace in the actual implementation

Identify what the key actually admits and whether a caller with an intended narrow key reaches another function or protected business operation.

## Implementation decisions

Identify function, host and administrative/master key scope without copying key material into reports. A function key may intentionally authenticate a shared integration; it does not identify an end user. Compare invocation admission with handler authorization, and account for an explicitly anonymous trigger or an alternate authenticated gateway before classifying key reachability.

## Discriminating verification

Use an owned function fixture with synthetic effects; compare an intended function key and a restricted function/action.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A publishable endpoint or a key parameter is not account administration authority; a handler can still enforce its own actor policy.

## Repair acceptance

Restrict key distribution/scope and handler permissions, then verify intended trigger calls and cross-function denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/azure-functions/function-keys-how-to)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
