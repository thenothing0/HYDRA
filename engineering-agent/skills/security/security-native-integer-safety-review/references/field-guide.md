# Native integer conversion and size arithmetic — decision procedure

## Establish the boundary

Record exact operand types, promotions, conversions, signedness and machine widths before comparing validation, allocation and consumption. Derive the accepted range mathematically; distinguish intentional modular arithmetic from a security contract.

## Smallest decisive verification

Use source proof and tiny boundary fixtures or an isolated harness with relevant integer/conversion instrumentation. Avoid huge allocations. Demonstrate the changed size/index/limit and actual consumer, not only an arithmetic wrap.

## Reject or narrow unsupported conclusions

Unsigned wrap is not itself undefined behavior. Generic undefined-behavior instrumentation does not cover every unsigned overflow or lossy conversion. A changed integer without a protected consequence is not yet a security finding.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Check representability before the operation/conversion and use consistent bounded types or supported checked arithmetic. Retest maximum valid, first invalid, negative/narrowing and allocation-versus-copy agreement on relevant widths.

## Evidence worksheet

typed arithmetic derivation; validation/operation order; width/ABI; minimal boundary values; downstream bound; actual/source-proved effect; instrumentation options; valid-range controls

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
