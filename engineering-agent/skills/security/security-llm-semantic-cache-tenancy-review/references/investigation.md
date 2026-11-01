# Investigation: Semantic response cache reuse across identities and private context

## Trace in the actual implementation

Determine whether semantically similar prompts reuse responses generated with another user private context or permissions.

## Implementation decisions

A vector match threshold determines similarity, not authority. Inspect whether the cache key or post-hit check binds tenant, entitlement, private context and model/tool policy. An intentionally public answer reused across users is a positive control; the material result is another identity receiving a synthetic private answer or action result it cannot independently obtain.

## Discriminating verification

Use an owned local cache with synthetic private markers, identical public wording and distinct users; compare cache hit and uncached controls.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Similar model outputs or an answer to public facts is not evidence of cross-user cache reuse without attribution.

## Repair acceptance

Scope cache entries to authorized context or public results and retest safe hits plus private-context isolation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
