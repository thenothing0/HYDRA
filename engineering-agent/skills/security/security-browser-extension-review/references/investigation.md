# security-browser-extension-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read manifest permissions, content/page bridges, runtime listeners and privileged background handlers. Record sender tab/frame/origin and which contexts can reach the listener.

## Decisive experiment and source trace

From an owned untrusted page, exercise the documented bridge with an inert request for a fixture resource. Trace sender provenance through to the privileged action. Compare the intended extension page and the untrusted page, keeping the resource/action constant.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Broad permissions alone do not show a reachable confused deputy. A content-script message must not be treated as an extension-page message merely because it carries an extension-selected action name.

## Repair acceptance

Authorize action/resource against validated sender context and narrow delegated capabilities. Retest expected extension UI, denied page/frame and the actual browser release/build.

## When the next edge is unavailable

If only a manifest is supplied, identify excessive-capability candidates and request the message handler/bridge before claiming reachable privilege use.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
