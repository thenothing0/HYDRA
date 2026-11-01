# security-firestore-rules-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read deployed rules, query shape, document paths, authentication claims and authoritative membership fields. Distinguish client SDK rules from privileged server SDK/IAM access.

## Decisive experiment and source trace

Use a local rules emulator or owned fixtures with A/B tenants. Compare a normal A query/read with a B document/query and inspect whether caller-writable document fields can manufacture the membership condition. Exercise writes against both existing and proposed document state where relevant.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Rules do not filter an arbitrary result set like application code; query compatibility matters. A server SDK bypassing client rules is expected and needs its own IAM/application authorization analysis.

## Repair acceptance

Bind document/query/write authority to trusted identity and protected membership state. Retest allowed query shapes, denied cross-tenant reads and writes that try to change authority fields.

## When the next edge is unavailable

Without deployed rules or actual query/index context, request them and avoid inferring production exposure from a source rules file alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
