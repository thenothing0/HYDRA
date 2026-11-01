# security-kubernetes-rbac-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect roles/bindings, service-account identity, namespace, aggregation and admission/workload creation context. Record exact resource, subresource and verb, not just a role label.

## Decisive experiment and source trace

Evaluate a specified low-privilege subject's effective action using read-only authorization inspection. If workload creation is involved, trace whether that workload can select a more privileged service account under actual admission policy; do not deploy it for proof unless separately within scope.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A wildcard role fragment or ability to create a pod is not automatically cluster-admin. Admission, namespace, identity selection and downstream permissions determine the reachable authority.

## Repair acceptance

Remove the evidenced excess binding/delegation while retaining intended controller/operator operations. Re-evaluate the prohibited action and normal workload behavior.

## When the next edge is unavailable

If admission or service-account selection rules are absent, record the conditional chain and request that specific constraint instead of completing the escalation by assumption.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
