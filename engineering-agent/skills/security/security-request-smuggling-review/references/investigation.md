# security-request-smuggling-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Record exact proxy/backend versions, protocol conversions, framing rules, connection reuse and any normalization layer. Establish the two parsers' interpretations before a probe.

## Decisive experiment and source trace

Prefer an isolated replica with two controlled requests on a dedicated connection and explicit frontend/backend logs. Use an inert canary to observe an actual message-boundary disagreement and which backend request consumes it. Bound bytes/time and terminate the fixture connection.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A timeout, 400 or duplicate framing header is not proof of desynchronization. No shared connection or consistent parser rejection may defeat the proposed chain. A single mock parser does not validate a real proxy stack.

## Repair acceptance

Use supported consistent framing/rejection across the actual stack and eliminate the evidenced ambiguous boundary. Retest ordinary persistent requests and the exact prior parser disagreement.

## When the next edge is unavailable

Without a permitted isolated environment, stop at a source/config hypothesis with the missing parser/connection evidence; do not involve unrelated client traffic.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
