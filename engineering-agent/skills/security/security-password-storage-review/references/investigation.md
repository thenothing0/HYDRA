# security-password-storage-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace enroll/verify/reset/rehash to the actual library and stored verifier parameters/version. Record salts, pepper boundary, input-length/Unicode handling and legacy migration.

## Decisive experiment and source trace

Use nonsecret fixture passwords and verifiers. Compare correct/incorrect verification and a successful legacy rehash, measuring only a bounded local sample under the intended resource budget. Inspect what happens when configured parameters or input exceed supported limits.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A hash-looking string is not proof of a password KDF or adequate work factor. A recommendation mismatch alone does not establish an online compromise. Never collect production password hashes or crack passwords for this review.

## Repair acceptance

Use supported current password-verifier configuration and safe migration after successful verification. Retest valid/invalid passwords, rehash and declared input/resource limits.

## When the next edge is unavailable

Without verifier format/library/parameters, request those nonsecret details and keep offline resistance conditional.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
