# security-kubernetes-workload-isolation-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read the admitted pod spec for all init/sidecar/app containers, host mounts/namespaces, security context and enforced admission policy. Record node/runtime and workload identity.

## Decisive experiment and source trace

Inspect whether a lower-trust submitter can obtain the host/device/capability access alleged by the finding. Use read-only evidence or an owned isolated replica; trace admission result to the effective container configuration rather than a manifest that was never admitted.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A missing hardening recommendation is not automatically a reachable escape. A privileged-looking source manifest rejected by admission does not prove deployed authority.

## Repair acceptance

Enforce the required isolation at admission/runtime and remove unnecessary host authority while preserving required workloads. Retest the original submitted configuration and an approved deployment.

## When the next edge is unavailable

If admitted configuration or runtime context is missing, state that deployment/isolation is unverified and request the effective spec/policy.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
