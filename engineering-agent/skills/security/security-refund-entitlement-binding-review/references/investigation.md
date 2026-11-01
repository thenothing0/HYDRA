# Investigation: Refund authority and amount/recipient binding to the original transaction

## Trace in the actual implementation

Follow requested amount/currency/recipient and order identity to the authoritative original transaction and cumulative refunded value.

## Implementation decisions

Determine whether refunds are cumulative across partial requests and which payment recipient/currency is authoritative. Provider acceptance, internal ledger credit and order state can diverge. A failed provider refund followed by client-visible success is not automatically money loss, but a duplicate spendable internal credit is a separate material effect.

## Operational method

Use an explicit owned ledger, for example captured1000, successful prior refund300 and pending reservation200 under a policy that reserves pending refunds: additional available amount is500. If that pending refund fails and its reservation releases, availability becomes700; the policy and final provider/internal states must agree. Allocate per-item refunds and reversal entries so a status retry cannot create another spendable credit. These numbers are synthetic minor units, not a universal merchant accounting rule.

## Discriminating verification

Use owned sandbox orders with synthetic amounts; compare valid partial refund with a foreign order or excessive cumulative request.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A refund-created response is not money movement; inspect accepted provider sandbox state and internal ledger consistently.

## Repair acceptance

Bind refund eligibility/value/recipient to original payment and reconcile atomic outcomes without duplicate credit.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
