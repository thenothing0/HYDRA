# Investigation: Admission webhook selection, authentication and failure behavior

## Trace in the actual implementation

Determine which operations/resources reach the webhook and whether equivalent API paths or webhook failures admit an object violating the intended invariant.

## Implementation decisions

Resolve webhook rules, namespace/object selectors, match conditions, failurePolicy and reinvocation behavior for the actual API operation. A fail-open timeout is material only when a required admission restriction is thereby skipped. Operator-supplied webhook configuration is privileged setup; do not label that setup itself an unprivileged bypass or cause production timeouts.

## Discriminating verification

Use an isolated cluster fixture with inert pods/config and compare compliant object, policy violation and controlled webhook unavailability.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A fail-open setting is not a demonstrated dangerous admission without an in-scope violated workload policy; an excluded object may be intentional.

## Repair acceptance

Align matching and failure behavior with the enforced invariant and retest availability recovery and legitimate admissions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
