# Investigation: Protected context disclosure through an LLM application response

## Trace in the actual implementation

Identify the protected information and its trust/entitlement boundary, then follow whether lower-trust input can cause its release to a different actor.

## Implementation decisions

Define the actual secret/data boundary before evaluating a model response. System instructions can be ordinary product text; disclosure requires protected material and evidence that the response derives from it rather than guessing. Use a synthetic hidden canary and public-text controls, keep uncertainty explicit, and separate authorized answer content from verbatim protected context.

## Discriminating verification

Use a local app or owned identities with a synthetic secret marker and legitimate question control; observe actual emitted content, not the model claiming access.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Generic system-prompt wording or public instructions are not inherently confidential data; a hallucinated secret is not disclosure.

## Repair acceptance

Remove unnecessary sensitive context and enforce entitlement outside model discretion, then retest authorized and restricted outputs.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
