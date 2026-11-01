# Investigation: Marketplace seller/customer settlement and fee allocation integrity

## Trace in the actual implementation

Follow client-selected seller/account IDs to payout recipient and reconcile gross, fees, refunds and net settlement.

## Implementation decisions

Track the server order seller, connected payment account and fee/refund allocation independently. A seller display ID may be public while settlement account selection is protected. Report the exact value or recipient mismatch established by provider sandbox and internal ledger, not a hypothetical full-platform theft chain.

## Operational method

For one owned order, reconcile gross captured amount with seller allocation, platform fee, tax/other contract allocations and linked refunds/chargebacks. Identify the actor allowed to change each destination or allocation and compare it with the provider sandbox settlement account actually selected. A visible seller identifier mismatch alone is not diverted funds; retain both provider and internal posting IDs and do not assume one fee convention for every marketplace.

## Discriminating verification

Use two owned sandbox sellers and a synthetic order; compare correct settlement with one foreign seller/account substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Public seller metadata is not settlement authority; a rejected provider account mismatch closes the proposed transfer path.

## Repair acceptance

Bind financial recipients to server order ownership and verify correct allocation and refund reversal.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
