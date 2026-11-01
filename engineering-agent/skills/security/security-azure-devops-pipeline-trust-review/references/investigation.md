# Investigation: Azure DevOps pipeline resource and service-connection trust

## Trace in the actual implementation

Trace editable code/templates/variables into a job with a privileged service connection, including approvals tied to a different artifact or branch.

## Implementation decisions

Inspect pipeline edit authority, protected-resource checks, service-connection authorization and the job token scope together. Approval of a resource does not necessarily approve every future script revision. Follow the checked source/ref and template expansion into the secret-bearing job; an untrusted pull request stopped before resource admission does not demonstrate credential exposure.

## Operational method

Retain the protected resource check configuration and actual evaluated run/ref. Required-template, branch-control, environment approval and service-connection pipeline authorization are distinct gates. Determine whether the connection is available to all pipelines or selected definitions and whether an editor can change the checked source after approval. The denial control must stop before the secret-bearing job; successful environment approval alone does not prove service-connection admission.

## Discriminating verification

Use an isolated pipeline fixture with inert publish output; compare a trusted run and a lower-trust template/resource change.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A connection name visible in YAML is not use authority; a denied approval or resource permission may already stop the path.

## Repair acceptance

Bind approvals/resources to the consumed revision and scope service connections, preserving legitimate releases.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
