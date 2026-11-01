# Investigation: Authorization of materialized batch dependency and result-reference targets

## Trace in the actual implementation

Trace whether an allowed batch operation authorizes each object/action, including mixed valid/invalid identifiers and omitted per-item fields.

## Implementation decisions

A batch may be intentionally atomic or partial-success; record that contract before judging mixed results. Check each action/object pair, not only IDs. Duplicate items can trigger separate lifecycle issues, but a failed foreign item plus successful owned item is expected under a documented partial model.

## Operational method

Specialize in batch dependencies/result references, not ordinary mixed-owner ID arrays. Retain the dependency graph and materialized target of every subrequest, including references to an earlier result. Authorization before placeholder resolution does not establish authority over the resolved object. Compare a literal owned target, an equivalent permitted reference and a reference resolving to a forbidden object; observe each committed operation under the declared atomic/partial contract. Route simple array BOLA to the object-authorization workflow.

## Discriminating verification

In an owned dependent batch, compare a literal allowed target with the same allowed target resolved through a previous result, then a result reference resolving to a forbidden object. Observe the materialized target, authorization point and committed per-item effect.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Endpoint-level access or one permitted item is not authority for every batch item; a rejected entire batch is not bypass.

## Repair acceptance

Authorize each item and define partial-failure semantics; retest mixed, allowed and duplicate-item batches.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
