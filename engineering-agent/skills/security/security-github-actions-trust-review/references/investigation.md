# security-github-actions-trust-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Read event triggers, checked-out ref, expression interpolation, token permissions, environment gates, actions pinning and runner lifecycle. Follow artifacts/caches from producer to privileged consumer.

## Decisive experiment and source trace

Construct a local event-to-job trust trace for an untrusted PR or artifact. Determine whether privileged execution consumes attacker-controlled code/content before an actual approval/trust boundary. Inspect exact checkout/run binding; do not run untrusted workflows with a privileged token for proof.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

pull_request_target is not itself a finding. A privileged workflow that consumes only trusted code with correctly bound reviewed artifacts may be safe. A checkout SHA and an artifact name are different provenance claims.

## Repair acceptance

Keep untrusted execution separate from privilege and bind promoted artifacts to trusted producer/run/digest. Retest normal contribution and the original untrusted-to-privileged path in an owned fixture.

## When the next edge is unavailable

If workflow dependencies, reusable workflows or artifact consumer are absent, request the specific missing stage; do not complete a token-theft chain from an event name alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
