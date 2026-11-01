# security-api-bola-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Open the resource model, tenant membership rule, object lookup, serializer and export/download consumer. Write down whether tenant membership, ownership, a share grant or a combination authorizes this action.

## Decisive experiment and source trace

Create private document B with a unique inert marker as owner B. Actor A first reads its own document, then requests B using the same A session. If the direct endpoint denies, trace the export relationship: can an A-owned export job accept document B? Compare the owner/tenant of both the job and every referenced document, at enqueue and consumption. Observe the exported marker or durable write, not just job creation.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An accepted job whose worker later rejects B is not a demonstrated document disclosure. A shared document is a legitimate control only under the recorded grant. Endpoint denial and a successful authorized owner read must use the same build.

## Repair acceptance

Bind every referenced object to the caller action policy before use, including nested and batched objects. For mixed-owner batches verify the documented atomic/reject/filter behavior and absence of forbidden content in exports, logs and job results.

## When the next edge is unavailable

Without a private-object policy, record the lookup as a candidate and request the ownership/share rule. Without worker access, name export consumption as the missing edge; do not infer its result from a queued status.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
