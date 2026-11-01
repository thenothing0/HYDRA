# Investigation: Kubernetes Secret storage encryption and effective read paths

## Trace in the actual implementation

Separate base64 representation, encryption at rest and API authorization. Trace access to plaintext through datastore backups, providers and permitted API readers.

## Implementation decisions

API authorization, etcd encryption and node/workload delivery protect different paths. A base64 field is not encryption, while a privileged API reader obtaining plaintext may be expected. Verify encryption-provider ordering, rotation/rewrite status and storage evidence without publishing real keys; configured encryption alone does not prove historical objects were rewritten.

## Discriminating verification

Use a local cluster/synthetic Secret and an owned storage snapshot to distinguish plaintext persistence from authorized API decryption.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Reading a Secret through an authorized API is expected even when at-rest encryption works; base64 alone is not encryption evidence.

## Repair acceptance

Protect storage/backups and effective read authority, verifying key rotation, rewrite and recovery behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
