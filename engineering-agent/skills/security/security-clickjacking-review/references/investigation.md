# security-clickjacking-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect framing policy on the exact sensitive page, its session behavior inside a frame and any confirmation/reauthentication step. Define the protected UI action.

## Decisive experiment and source trace

In an owned framing page, verify the victim test account can actually load and interact with the sensitive UI under the real browser credential policy. Use an inert state change and record the interaction required. Compare direct legitimate use and framing after the fix.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A missing header or frameable public landing page is not proof that a protected operation can be induced. UI needing a separate unspoofable confirmation may change the supported impact.

## Repair acceptance

Set an appropriate CSP frame-ancestors policy on affected responses and preserve approved embedding requirements. Test the actual page and legitimate embedded integration if one exists.

## When the next edge is unavailable

If browser access is unavailable, state the missing frame/session/interaction evidence; do not infer exploitation from a header scan alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
