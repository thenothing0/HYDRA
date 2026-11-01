# security-container-build-secrets-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Open Dockerfile, context ignore rules, build arguments, secret mounts, layer/export metadata, build logs and cache export/access. Identify actual sensitive inputs using synthetic markers.

## Decisive experiment and source trace

Build only an owned fixture with a fake secret marker and inspect relevant exported layers/history/logs/cache. Distinguish copying a secret then deleting it in a later layer from avoiding persistence in the first place. Record the build engine/settings used.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A secret mount directive alone is not a leak; using a fake marker in an inaccessible build-only context does not establish recipient exposure. Conversely, deleting a file in the final image does not erase prior exported layers.

## Repair acceptance

Use supported ephemeral secret delivery and prevent the evidenced persistence/export path. Retest required build behavior and search the actual distributed artifacts for the fake marker.

## When the next edge is unavailable

Without build/export access, give a source trace of the persistence candidate and request the relevant layer/cache artifact; never print real build secrets.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
