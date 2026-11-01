# Investigation: Secret Manager version access and conditional IAM scope

## Trace in the actual implementation

Separate metadata, secret-version access and permission to change IAM/version state. Evaluate the actual resource/condition context used by the workload.

## Implementation decisions

Resolve the full project/secret/version and any alias at access time. Metadata/list permissions and secret-version payload access differ. An alias such as latest can change during rotation; compare the authorized resource and actual selected version, including conditional IAM context, rather than assuming permission on one version generalizes to all secret data.

## Discriminating verification

Use an owned secret with a synthetic value and compare intended principal/version with a restricted owned principal.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A secret name or version listing is not access to secret bytes; a missing version is not authorization evidence.

## Repair acceptance

Constrain access and delegation to intended secrets/versions and retest permitted rotation workflows.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/secret-manager/docs/access-control)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
