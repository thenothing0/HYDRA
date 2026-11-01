# security-aead-nonce-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Record primitive/library, stable key identity/rotation domain, nonce allocator persistence and authenticated-data contract. Include restart, concurrent writers and rollback behavior.

## Decisive experiment and source trace

With a nonsecret fixture key, instrument allocation across two writers/restarts and compare key-identity/nonce pairs. Separately use a local valid ciphertext and an invalid tag/context to trace whether plaintext is used before authentication or under the wrong account/purpose.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Equal nonces under different keys are not the same reuse claim. Random-looking values do not establish uniqueness. Tag bytes being stored do not prove verification before use.

## Repair acceptance

Meet the chosen primitive's actual nonce/key contract and verify authenticated context before use. Retest concurrency/restart/rotation and valid data migration/decryption.

## When the next edge is unavailable

If primitive or key-identity allocation is unknown, request it; do not generalize requirements from an algorithm family or expose real keys.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
