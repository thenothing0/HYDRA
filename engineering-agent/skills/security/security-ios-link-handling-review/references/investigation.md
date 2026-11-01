# security-ios-link-handling-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read associated-domain entitlements, association file, universal/custom URL handlers and downstream account/action selection. Record actual signed build and OS behavior.

## Decisive experiment and source trace

On an owned test device compare a valid link with one controlled parameter/account/action change. Observe the app's consumed destination and whether it commits a protected operation or links the wrong account. Keep browser/app transition and confirmation prerequisites visible.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Registering a URL scheme or opening a page is not account takeover. A custom scheme can have weaker routing guarantees than universal links, but the protected consumer still determines impact.

## Repair acceptance

Bind links to intended routing/account/action state and supported platform association checks. Retest legitimate links, the original parameter confusion and required confirmation behavior.

## When the next edge is unavailable

If only association metadata is available, request handler/consumer code and mark device routing and protected effect unexecuted.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
