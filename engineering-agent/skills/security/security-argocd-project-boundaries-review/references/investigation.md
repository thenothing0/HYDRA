# Investigation: Argo CD project repositories, destinations and controller delegation

## Trace in the actual implementation

Follow application source/destination and project selection into resources the controller applies. Inspect who may modify the project or privileged application fields.

## Implementation decisions

Evaluate AppProject source repositories, destinations, resource allowlists and repository/controller credentials together. A project allowing a namespace may still need to restrict cluster-scoped resources and destination identity. Argo CD administrative editing is not an unprivileged bypass; demonstrate the authority of the actual application author and the rendered resources the controller will apply.

## Operational method

Check who may edit AppProject versus who may select Application.spec.project. Inspect destination namespace as a security capability: deployment into the Argo CD installation namespace can permit control over Argo resources, even with a restricted source list. Trace permitted rendered resources into controller/app credentials and project admission without applying them to production. Source allowlisting alone does not establish safety of an administrative destination.

## Discriminating verification

Use an isolated GitOps fixture and inert manifests; compare permitted application sync with a forbidden repo/namespace/resource selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Read access to an application or a powerful controller identity is not escalation if application/project mutation is denied.

## Repair acceptance

Constrain project/application authority and final cluster admission, retesting legitimate reconciliation and forbidden destinations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
