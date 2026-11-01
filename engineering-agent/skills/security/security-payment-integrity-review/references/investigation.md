# security-payment-integrity-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map trusted catalog/order amount/currency/recipient, payment provider event, order binding and paid-state transition. Use a provider sandbox or inert local payment fixture.

## Decisive experiment and source trace

Compare a legitimate order payment with one caller-controlled mismatch derived from source: amount, currency, order or recipient. Inspect trusted provider event verification and the durable order ledger. An accepted checkout request is not proof of settled/fulfilled state.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A client price used only for display is not price tampering. A signed provider event can still be bound to the wrong order, while a rejected mismatched event defeats that specific hypothesis.

## Repair acceptance

Compute authoritative order values server-side and bind verified payment evidence to the exact order/recipient/state with idempotency. Retest legitimate settlement, original mismatch and bounded duplicate event.

## When the next edge is unavailable

Without sandbox/event/ledger evidence, request the missing stage and avoid real charges, refunds or claims of financial loss.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
