# Investigation: Persistent agent memory ownership, retrieval and update authority

## Trace in the actual implementation

Trace who may persist or modify memory and which user/tenant receives it after later retrieval, including merged or summarized memories.

## Implementation decisions

Resolve who owns a memory item and who may insert, update, retrieve or delete it. A shared team memory may intentionally cross individual accounts; compare against its declared audience. Follow stable tenant/user identifiers through retrieval filters, summarization and cache reuse, including account switching, rather than equating semantic similarity with an ownership grant.

## Operational method

Retain provenance and permitted audience for each input item contributing to a summary or merged memory. The derived object audience must follow the declared intersection/declassification policy, not whichever namespace stores the summary. Compare a permitted team summary with one including a restricted synthetic item, then revoke/delete its source entitlement and inspect derived-memory reuse. A direct namespace filter alone does not establish derived-data isolation.

## Discriminating verification

Use two owned actors with distinct synthetic memory markers; compare permitted recall and a controlled foreign namespace/update request.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A model recalling public shared knowledge is expected; similarity alone does not prove a specific private memory was retrieved.

## Repair acceptance

Bind memory writes/retrieval/retention to current actor authority and verify deletion and entitled recall.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
