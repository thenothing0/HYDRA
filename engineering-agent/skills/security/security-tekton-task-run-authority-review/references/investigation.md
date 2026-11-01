# Investigation: Tekton TaskRun parameters, workspaces and execution identity

## Trace in the actual implementation

Trace lower-trust parameters or remotely resolved task content into a workload with privileged credentials, volumes or service identity.

## Implementation decisions

Resolve referenced Task/ClusterTask/bundle content, admitted service account, workspace/PVC mounts and parameter substitution into executable steps. A parameter appearing in a script is different from an argv element. The TaskRun submitter may intentionally hold deployment authority; show where the actual restricted submitter can borrow a stronger execution identity.

## Discriminating verification

Use an isolated cluster task with inert output; compare permitted parameter use and a forbidden task/workspace/service-account selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Task expressiveness is not escalation if only an appropriately trusted operator may create the run.

## Repair acceptance

Constrain task sources and run authority, preserving approved parameterization and workspace isolation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://tekton.dev/docs/pipelines/taskruns/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
