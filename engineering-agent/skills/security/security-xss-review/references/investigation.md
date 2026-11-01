# security-xss-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Trace a controlled value from storage/URL/message through transformations to its final DOM/template context. Record origin, browser, CSP/Trusted Types enforcement, victim role and who can deliver the value.

## Decisive experiment and source trace

Use an inert local browser marker at the actual consumer, with no data exfiltration. Compare text rendering against HTML/attribute/URL/JS interpretation as applicable. For stored content, use a separate controlled viewer to establish reach beyond the submitting account. Inspect parsed DOM and execution, not only the original response text.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Escaped reflection and markup assigned as text to an ordinary text-bearing element are not XSS. A script/style consumer or later reparse requires its own interpretation review; the API name alone is not a universal safety guarantee. A dangerous-looking sink may receive only trusted constants. Self-only behavior and CSP-blocked execution need their real prerequisites and supported impact, not an invented account takeover.

## Repair acceptance

Use a safe consumer or context-appropriate encoding/sanitization for the required rich-content contract. Test the original data flow, legitimate formatting and one alternate transformation evidenced in source.

## When the next edge is unavailable

If no browser/runtime is available, provide the complete source-to-sink path and missing interpretation/attacker-delivery evidence; do not claim a dialog or script ran.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
