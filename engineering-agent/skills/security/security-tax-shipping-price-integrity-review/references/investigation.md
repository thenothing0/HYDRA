# Investigation: Configured tax/shipping calculation and quote-to-fulfillment integrity

## Trace in the actual implementation

Trace client inputs and quote IDs into the server total and the address/service actually fulfilled. Distinguish recalculated estimates from committed amounts.

## Implementation decisions

Bind the quote to address, service, currency, quantity and applicable time policy. A merchant may deliberately honor a historical guaranteed quote. Compare final charged and fulfilled service values; do not call a legitimate estimate update or tax-inclusive display convention a price manipulation.

## Operational method

Retain the configured calculation policy: tax-inclusive/exclusive prices, shipping taxability, currency minor units, per-line versus invoice rounding and guaranteed-quote lifetime. Recompute an owned quote under that same policy, then change address/service/weight or a rounding boundary and inspect the final charge and fulfilled service. A mismatch between two legitimate rounding conventions is not a security finding; identify an unauthorized determinant change or value beyond the declared tolerance. This does not determine legal tax obligations.

## Discriminating verification

Use a configured synthetic tax/shipping calculation with its inclusion, rounding and currency policy. Change one address/service/weight or rounding-boundary determinant and compare authorized quote, final charge and fulfilled service.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A transient displayed estimate is not an undercharge; inspect authoritative charge and fulfillment state.

## Repair acceptance

Recalculate or bind all quote determinants and retest legitimate address changes and stale-quote rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
