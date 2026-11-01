# security-webhook-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Identify provider protocol/version, exact-byte signature verification, endpoint secret/key selection, event/account binding and replay/idempotency state. Separate inbound webhooks from outbound URL fetchers.

## Decisive experiment and source trace

With owned synthetic events compare a valid event, tampered raw body and bounded duplicate delivery. Inspect durable protected state and whether the verified event account/object matches the local recipient. Preserve raw bytes used for signing rather than reserializing JSON for the test.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A 200 acknowledgement is not a protected commit. Signature verification alone does not prove order/account binding or idempotency, and provider timestamp/retry rules are not interchangeable.

## Repair acceptance

Use the provider-supported raw-byte verification and bind event/account/object/action before idempotent commitment. Retest legitimate retries, tampering and the original wrong binding.

## When the next edge is unavailable

If provider/version or actual verification bytes are unknown, request them rather than assume one universal HMAC/timestamp scheme.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
