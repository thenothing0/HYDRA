# Investigation: Funded issuance and transferable bearer gift-card value lifecycle

## Trace in the actual implementation

Trace each benefit to its authoritative debit/credit and eligibility rule, including partial redemption, rollback and refunded issuance.

## Implementation decisions

Track issued, available, reserved, redeemed and refunded value separately. An optimistic balance may later reconcile without permitting extra spend. Show two authoritative debits/credits or another forbidden benefit under the same eligibility rule before classifying a duplicate-redemption defect.

## Operational method

Specialize in the funded issuance and transferable bearer-card lifecycle. Retain funding/capture, activation, transfer, redemption and reversal entries for one synthetic instrument; separate deliberately unfunded promotional value. Verify issued spendable value against authorized funding/credit and track the owner of each debit when a card changes hands. Knowing a display code is not proof of a valid bearer secret or authority to redeem someone else card.

## Discriminating verification

Use synthetic funding, activation and transfer entries for one test card, then redeem and reverse under the owner policy. Compare spendable issuance against funding/promotional authority and ensure the same debit/transfer is not counted twice.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A displayed balance change is not additional spendable value; verify ledger and redemption authority, not UI arithmetic.

## Repair acceptance

Preserve value conservation and atomic redemption, then test legitimate partial use, replay rejection and rollback.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
