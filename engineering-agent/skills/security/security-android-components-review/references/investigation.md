# security-android-components-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect the merged release manifest, exported components, permissions, caller checks, intent parameters and URI grants. Record Android/version/build and intended inter-app contract.

## Decisive experiment and source trace

In an owned test app/device invoke the component from a separate low-privilege test app with a harmless fixture URI/action. Compare its protected effect with the legitimate app flow and inspect whether identity is checked before privileged work.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An exported component is not inherently vulnerable. A signature permission, caller check or restricted URI grant may enforce the intended contract. A debug manifest may not describe release exposure.

## Repair acceptance

Apply the required caller/action/resource check and narrow component/grant exposure. Retest legitimate integrations, the original untrusted caller and URI grant lifetime where relevant.

## When the next edge is unavailable

Without a release manifest/device, provide static exposure/reachability analysis and explicitly mark actual cross-app behavior unexecuted.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
