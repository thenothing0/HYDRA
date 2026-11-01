# Investigation: LLM-driven fetch loops and cost admission at external-tool boundaries

## Trace in the actual implementation

Trace lower-trust model output into repeated fetch/tool calls and identify admission before each network/cost increment.

## Implementation decisions

Bound the complete tool-call graph, including retries, redirect hops, pagination and nested model invocations, before considering per-request limits. Distinguish a configured authorized budget from a caller ability to exceed it. Use tiny local cost units and deterministic ceilings; do not generate substantial provider charges or infer monetary loss from a long transcript alone.

## Operational method

Inspect atomic budget reservation before parallel fan-out, not only a sequential decrement after calls finish. Retain requested, reserved, completed, canceled and reconciled cost units for each child call/retry. In a tiny deterministic fixture start two calls competing for one remaining reservation and verify the configured cap; distinguish asking for cancellation from stopping already charged in-flight work. Never generate significant provider cost for this review.

## Discriminating verification

Use local deterministic stub tools with tiny budgets and bounded fixtures; compare normal completion and a loop exceeding the configured count/cost.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A model suggesting many calls is not resource exhaustion if the orchestrator enforces a budget; do not generate production load.

## Repair acceptance

Enforce cumulative budgets/cancellation at the tool executor and verify useful short tasks and bounded termination.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
