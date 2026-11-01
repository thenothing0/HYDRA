# Investigation: Jenkins job/agent trust and controller or credential delegation

## Trace in the actual implementation

Follow who can edit pipeline code and select an agent/credential into actual privileged operations, including workspace reuse between trust classes.

## Implementation decisions

Distinguish controller execution, trusted shared libraries and agent workspace execution. Credentials scoped to a folder/job are still available to scripts deliberately authorized in that job. Inspect job configuration and agent label restrictions before assuming an untrusted contributor can land on a sensitive agent; ordinary workspace access is not controller compromise.

## Operational method

Labels select scheduling candidates; they are not a node-use authorization boundary. Collect the installed enforcement mechanism, such as effective job restrictions independent of label expressions, and the actual job execution identity/node Build permission rules where configured. Inspect Agent-to-Controller Access Control for remoting requests from a lower-trust agent, not a reversed controller-to-agent control; also inspect workspace reuse/concurrent executors during credential binding. Compare allowed versus forbidden job placement before secret injection using supplied configuration and an inert marker. No plugin installation or access to another build credentials is implied.

## Discriminating verification

Use an isolated Jenkins/local runner fixture with inert markers; compare an intended trusted job and a lower-trust job requesting the protected context.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A credential identifier visible in a Jenkinsfile is not proof that the job can retrieve or use it.

## Repair acceptance

Separate trust classes and constrain job/agent/credential delegation; verify approved builds and denied context acquisition.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.jenkins.io/doc/book/security/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.

- [Additional implementation reference](https://www.jenkins.io/doc/book/security/controller-isolation/)
