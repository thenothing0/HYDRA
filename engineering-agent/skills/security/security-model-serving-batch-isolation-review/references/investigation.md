# Investigation: Multi-tenant model-serving request and response isolation in batching

## Trace in the actual implementation

Trace tokens/outputs/state through dynamic batching and cache reuse to the correct caller, especially canceled/retried requests.

## Implementation decisions

Track request-to-output slots through dynamic batching, cancellation, streaming and KV/prefix cache reuse. Shared model weights and public prompt prefixes may be expected; private prompts, generated tokens and tenant-specific adapters have different isolation requirements. Use distinguishable synthetic tenants and observe final routing, not only an internal tensor allocation that cannot affect another request.

## Operational method

Retain request ID, tenant, slot generation, cache provenance and final stream owner through admit, cancel, release and reallocate events. Compare cancellation of requestA followed by slot reuse for B with a legitimate same-tenant prefix-cache hit. The implementation trace must show which generation owns each emitted token/response; a toy scheduler demonstrates only its own behavior and cannot certify a real serving runtime or accelerator cache.

## Discriminating verification

Use a local deterministic serving stub or owned isolated runtime with distinct synthetic prompt markers and bounded batches.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Semantically similar output is not cross-request leakage without attributed private marker/state; public model knowledge is not tenant data.

## Repair acceptance

Bind cache and stream ownership through batch lifecycle and verify canceled, retried and simultaneous entitled requests.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
