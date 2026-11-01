# security-http-response-splitting-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace untrusted input to the response-header API and actual serialized HTTP version/server stack. Separate header value validation from log or body rendering.

## Decisive experiment and source trace

Use an isolated local client/server with an inert marker. Inspect raw serialization for the exact suspected line-boundary input and compare a normal header value. Determine whether extra headers/messages are actually emitted, rejected or encoded by the framework.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Control characters in application logs are not wire-level response splitting. A client display artifact or an HTTP/1 hypothesis does not establish behavior over a different protocol stack.

## Repair acceptance

Use supported header APIs and reject prohibited characters at the serialization boundary. Retest legitimate values and the original serialized anomaly on the affected stack.

## When the next edge is unavailable

If raw protocol evidence/runtime is missing, keep the sink as a candidate and request serialization behavior rather than infer a second response.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
