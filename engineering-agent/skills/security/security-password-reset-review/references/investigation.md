# security-password-reset-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace reset request, recipient selection, token generation/storage, validation, password commit and session policy. Record which account and purpose a token is bound to.

## Decisive experiment and source trace

With two controlled accounts and a local/owned mailbox, request A's reset and compare the token's validated account with any caller-supplied account/recipient field at consumption. Complete one intended reset, then make a bounded reuse attempt against the same fixture token. Inspect account credential state, not just response text.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A reset email arriving or a token being visible to its intended recipient is normal. A generic success response can hide rejection. Password policy or mail enumeration observations are different root causes.

## Repair acceptance

Bind recipient, account, purpose, lifetime and one-time consumption atomically. Retest wrong-account consumption, reuse and valid recovery; assess session invalidation against the product's declared contract.

## When the next edge is unavailable

Without a controlled mailbox or token-consumption code, review issuance statically and identify consumption binding as the missing decisive edge.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
