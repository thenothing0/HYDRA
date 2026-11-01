# security-kubernetes-network-policy-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect selected pod labels/namespaces, all applicable policies, CNI/enforcement capability and actual source-to-destination network path. Include DNS/egress requirements where relevant.

## Decisive experiment and source trace

Resolve one prohibited ingress/egress tuple and one required service path using policy composition and an owned isolated reachability check where available. Check which pods each selector actually selects; a policy file with no matching pods is not evidence of protection.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

NetworkPolicies compose allow behavior; a restrictive-looking policy may coexist with another allowance. Host networking, service translation and CNI details can affect the claimed result.

## Repair acceptance

Correct the evidenced selectors/ports/peers under the real CNI contract. Retest the prohibited tuple, required service/DNS path and unchanged application availability.

## When the next edge is unavailable

Without CNI or actual labels/policy set, provide a conditional graph and request that missing enforcement context, not a universal segmentation claim.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
