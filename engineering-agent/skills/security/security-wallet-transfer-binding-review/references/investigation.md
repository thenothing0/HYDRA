# Investigation: Approved wallet transfer version and per-currency balanced postings

## Trace in the actual implementation

Bind the approved transfer intent to sender wallet, recipient, amount and currency through execution, including limits and account state.

## Implementation decisions

Confirm that transfer approval covers the immutable amount, currency, sender and destination actually posted. Pending, failed and reversed ledger entries are not final spendable credit. A cross-currency display mismatch needs authoritative posting evidence, and the sandbox must never represent actual customer funds.

## Operational method

Use signed minor-unit postings per currency. For a same-currency synthetic transfer with fee, debit from sender must equal recipient credit plus fee postings; held funds are not yet final credit. For exchange, record the approved rate/version and both currency ledgers rather than adding unlike units. Bind postings to the approved transfer version and link reversals to original entries; a retry must not generate a second independent credit under the same one-use policy.

## Discriminating verification

Record synthetic held/posted per-currency entries for one approved transfer, including fee or FX terms when applicable. Compare valid one-use posting with a changed approved-version tuple and a duplicate delivery/reversal; inspect both debit and credit sides.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A pending transfer ID or altered client summary is not a posted unauthorized transfer; inspect both ledger sides.

## Repair acceptance

Bind approved intent to atomic debits/credits and verify legitimate retries plus rejected substitutions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
