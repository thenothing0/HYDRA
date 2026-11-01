# Investigation: Inventory reservation ownership, expiry and allocation transitions

## Trace in the actual implementation

Follow reserved units through confirm, expiry and cancellation; check whether a caller can confirm another reservation or obtain allocation twice.

## Implementation decisions

Separate stock reservation from final allocation and fulfillment. The expiry-versus-confirm order should be deterministic in the local fixture. A restored reservation counter with an uncommitted checkout proves no extra allocation; deliberate oversell/backorder policy must be documented before asserting conservation.

## Operational method

Write the owned state table: available stock becomes held on reserve, held becomes allocated on confirm, and held returns to available on expiry/release. Under a no-oversell fixture, available+held+allocated stays equal to initial stock; adapt for documented backorders. Schedule confirm versus expiry deterministically, then repeat release delivery and inspect authoritative counters/allocations. A UI stock label or a rejected confirmation is not extra fulfillment.

## Discriminating verification

Use a tiny local stock fixture with two owned customers; compare rightful confirmation with stale/foreign reservation and inspect allocation state.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A reservation accepted by the UI is not a fulfilled allocation; documented overbooking must be distinguished from the asserted invariant.

## Repair acceptance

Bind reservation owner and atomic stock transitions, testing expiry/confirm ordering with deterministic local barriers.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
