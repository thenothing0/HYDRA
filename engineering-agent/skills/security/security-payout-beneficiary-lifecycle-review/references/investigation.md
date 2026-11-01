# Investigation: Payout beneficiary changes and confirmation-to-execution binding

## Trace in the actual implementation

Trace which beneficiary version was approved and which version the queued payout resolves, especially edits after confirmation.

## Implementation decisions

Determine whether confirmation approves a beneficiary identity or an immutable beneficiary version. A queued payout resolving a later changed destination can violate a version-bound approval. A label change with the same account identifier is not altered routing; verify the actual sandbox destination.

## Discriminating verification

Use a sandbox beneficiary fixture with synthetic destinations; compare approved payout with a post-approval destination change.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An edited display label is not changed funds routing; show the effective destination used by the sandbox execution.

## Repair acceptance

Bind payout approval to immutable beneficiary intent and retest allowed updates, cooldown and execution.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
