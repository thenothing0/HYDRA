# Investigation: Atomic security invariants across composed API operations

## Trace in the actual implementation

Identify a policy that must remain true across operations and whether an early permitted mutation persists when a later prerequisite fails.

## Implementation decisions

Write the exact invariant crossing the transaction before constructing the fixture. A documented best-effort API does not imply financial atomicity, and a transaction rollback does not undo external side effects automatically. Inspect database and external stub state separately when the operation spans both.

## Discriminating verification

Use a small local synthetic batch with a deliberate second-step denial and inspect final state, alongside a legitimate successful batch.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A documented partial-success API is not automatically broken; establish the intended all-or-nothing security invariant.

## Repair acceptance

Align transaction/compensation behavior with the invariant and retest failures at each material boundary.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
