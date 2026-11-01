# Investigation: Systems Manager command/session delegation to managed instances

## Trace in the actual implementation

Trace who chooses a document/target and whether permitted parameters delegate unintended process or instance authority. Separate SendCommand from session or document-update permissions.

## Implementation decisions

Separate SendCommand, StartSession and document creation/update/default-version selection. Evaluate target conditions against actual mutable instance tags and the selected document version. IAM permission to invoke a document does not sanitize its parameters: inspect the installed agent/document interpolation behavior. Session shell access and one constrained document action carry different effective authority.

## Discriminating verification

Use an isolated owned managed-node fixture or source-policy proof with an inert command document; compare intended target/document and an out-of-policy selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Access to an instance inventory is not command execution. Never test with destructive shell commands or unrelated production instances.

## Repair acceptance

Bind document/target/parameter authority and verify permitted diagnostics and rejected delegation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/systems-manager/latest/userguide/security-iam.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
