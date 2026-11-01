# Investigation: Approval-to-command binding across agent execution and retries

## Trace in the actual implementation

Trace the exact reviewed action into the executed process, including changed arguments, environment, cwd or substituted scripts after approval.

## Implementation decisions

Bind approval to executable, argv, working directory, environment and relevant script/input identity. Textually identical shell commands can execute changed files or resolve a different executable. Distinguish an intentionally approved general shell capability from approval of one immutable operation, and verify whether retries or edits invalidate the specific approval contract.

## Discriminating verification

Use inert local command stubs that record argv/cwd; compare an approved action and a deliberately modified subsequent action.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An approval for a displayed command is not a generic grant to related actions; conversely, repeated approval is unnecessary when the actual authorized action is unchanged.

## Repair acceptance

Bind approval to the security-relevant execution object and preserve legitimate idempotent retries.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
