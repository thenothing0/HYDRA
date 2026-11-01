# security-csrf-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map state-changing actions, ambient browser credentials, token/origin checks and cookie policy. Record the specific attacker origin and real victim prerequisites.

## Decisive experiment and source trace

Using two owned origins and a disposable account, submit the smallest state change a browser can actually deliver cross-site. Inspect durable state and compare the legitimate flow. If a token exists, verify its binding/validation at the action, rather than merely checking that a field is present.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A request requiring a nonambient secret not available to the attacking origin may defeat the hypothesis. A command-line client can forge headers and does not prove a browser can send them; response readability is not required for a CSRF state effect.

## Repair acceptance

Apply supported CSRF/session-origin defenses at the action boundary while retaining required cross-origin flows. Retest legitimate submission, the evidenced cross-site request and alternate state-changing routes.

## When the next edge is unavailable

Without cookie/credential behavior or a controlled state oracle, keep the claim unverified and request those prerequisites before further requests.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
