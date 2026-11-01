# security-ci-artifact-provenance-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect producer identity/event/ref, immutable artifact digest, provenance/attestation and the release consumer's verification policy. Record run identity, not only display names.

## Decisive experiment and source trace

In a local/owned pipeline fixture compare an approved artifact with one from an untrusted run sharing the same artifact name. Determine whether verification binds the exact consumed bytes to the approved producer, event/ref and release context.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A checksum delivered beside an artifact by the same untrusted producer establishes integrity of a transfer, not producer trust. A signature existing somewhere does not prove enforcement at consumption.

## Repair acceptance

Verify trusted producer/run and immutable digest before privileged promotion. Retest legitimate release, wrong producer and byte substitution at the actual consumer.

## When the next edge is unavailable

If attestation policy or artifact selection is missing, request it and keep provenance acceptance unverified.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
