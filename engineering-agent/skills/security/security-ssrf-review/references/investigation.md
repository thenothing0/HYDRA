# security-ssrf-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Read the exact URL parser/client, redirect and retry settings, DNS resolution/connection path, proxy behavior and documented allowed destinations. Identify which bytes the caller can influence.

## Decisive experiment and source trace

Use an owned allowed endpoint and a separate owned denied endpoint. If redirects are enabled, make the allowed fixture redirect to the denied fixture and correlate a unique application-fetch marker at each hop. For DNS changes, inspect whether the connected address is the one validated; preserve hostname/SNI/certificate verification when evaluating a proposed pinned-address repair.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A public fetch feature or DNS lookup alone is not forbidden HTTP reachability. A callback from the tester's browser is not a server fetch. Absence of a callback without a working allowed control is inconclusive.

## Repair acceptance

Enforce destination policy on actual connections, redirect hops and relevant retries; retain correct TLS peer validation. Retest legitimate fetches and denied callbacks without cloud-metadata or unrelated internal probes.

## When the next edge is unavailable

If the allow/deny destination policy or runtime resolution path is missing, request that evidence. Report only the observed request boundary, not unproven credential theft.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
