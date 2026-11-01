# security-aws-object-storage-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read bucket/access-point/object policies, public-access controls, ownership/ACL settings and the signed-URL issuer where relevant. Establish exact object sensitivity and caller identity.

## Decisive experiment and source trace

On an owned bucket with synthetic objects, compare the expected recipient with a prohibited anonymous/other-account read or write only as permitted. For signed URLs, trace who may mint a URL for which object/action and its lifetime; do not list or download unrelated bucket contents.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A public website object can be intentionally readable. A public-looking policy may be constrained by effective controls. A valid recipient using an intended signed URL is not proof of excess authority.

## Repair acceptance

Repair the effective bucket/object or URL-issuer boundary and preserve required publishing. Retest the exact denied tuple and intended owner/recipient access, including relevant access points.

## When the next edge is unavailable

Without effective policy or owned synthetic objects, review supplied configuration and leave actual exposure unverified.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
