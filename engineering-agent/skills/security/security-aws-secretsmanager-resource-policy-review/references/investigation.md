# Investigation: Secrets Manager resource-policy and version access across principals

## Trace in the actual implementation

Evaluate the actual principal and resource/condition context, then distinguish metadata read, secret-value read and changing a version/staging label.

## Implementation decisions

Resolve the requested secret ARN and VersionId/VersionStage, including which versions a policy actually permits. Cross-account access can require both secret and customer-managed KMS-key authority. A readable policy or a GetSecretValue denial caused by KMS does not prove another actor can retrieve plaintext; preserve the blocked edge and inspect rotation identities separately.

## Discriminating verification

Use a secret containing only an owned synthetic marker; compare the intended role with another owned role and inspect the exact requested version.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

List/describe permission is not GetSecretValue authority, and a KMS denial must not be attributed to a different resource policy.

## Repair acceptance

Narrow effective value/version authority and retest allowed retrieval, restricted principals and version lifecycle.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
