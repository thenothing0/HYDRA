# Investigation: GitLab CI source trust and protected variable/runner exposure

## Trace in the actual implementation

Trace lower-trust YAML/code/includes into jobs that receive protected material or trusted runner access. Preserve the exact event/ref permission context.

## Implementation decisions

Resolve project/fork identity, pipeline source, branch/tag protection and the actual conditions for protected variables and runners. Masking only changes display behavior; it does not prevent a running script from using a value. A rejected fork pipeline before secret-bearing execution is an effective boundary for that case, not proof of exposure.

## Operational method

Distinguish a fork-project pipeline from a parent-project pipeline executing configuration from a fork merge request. Retain project IDs, pipeline source, protected refs/runners and the installed-version protected-resource access settings. A fork pipeline rejected before secret admission is a denial; parent execution using untrusted fork configuration requires a separate source-to-secret-bearing-job trace. Masked output alone is not proof that the running job cannot use the secret.

## Discriminating verification

Use an isolated pipeline fixture with a synthetic secret marker and inert job; compare trusted ref and lower-trust merge-request configuration.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A variable name or protected runner tag is not material access if the pipeline policy withholds it.

## Repair acceptance

Bind protected context to trusted source/includes and retest legitimate releases without leaking real secrets.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
