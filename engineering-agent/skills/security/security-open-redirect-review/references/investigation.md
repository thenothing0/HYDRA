# security-open-redirect-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace redirect destination input, parsing, canonicalization, allowlist and the flow using the redirect. Record whether it participates in a sensitive callback or merely general navigation.

## Decisive experiment and source trace

Use an owned benign destination and the expected same-origin destination. Observe the actual browser/server Location resolution after transformations. For a claimed token or account chain, trace the additional sensitive flow separately rather than assuming any external redirect leaks credentials.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An external-link feature may intentionally navigate off-site. A displayed URL or rejected destination is not a redirect. Phishing potential does not by itself demonstrate account takeover.

## Repair acceptance

Use approved destination identifiers or robust parsing against the feature's allowed origin/path policy. Retest legitimate navigation and the exact originally accepted disallowed destination.

## When the next edge is unavailable

Without a destination policy or sensitive consumer, describe navigation behavior and unresolved impact; do not invent program eligibility.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
