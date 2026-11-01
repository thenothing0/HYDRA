# security-android-webview-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace trusted/untrusted navigation, JavaScript bridge registration, message channels, origin rules and native operations. Record Android/WebView version and frame scope.

## Decisive experiment and source trace

Use owned local content to compare the intended trusted page with an untrusted navigation/frame reaching an inert native operation. Inspect which origin/frame supplied the message at the native consumer and whether navigation changes the trust context.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

JavaScript enabled or a bridge method existing is not sufficient. A bridge inaccessible to attacker-controlled content may defeat the path; top-level URL checks may not describe subframe/message behavior.

## Repair acceptance

Restrict navigation/bridge capabilities and enforce supported caller-origin/frame checks at sensitive operations. Retest intended web content, untrusted navigation and the evidenced frame/channel path.

## When the next edge is unavailable

If bridge registration or navigation source is missing, request it and avoid claiming native code execution from WebView settings alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
