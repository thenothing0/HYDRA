# Investigation: CSI external-secret mount identity and workload/resource selection

## Trace in the actual implementation

Trace who chooses external secret identifiers and which workload identity the provider uses at mount/refresh.

## Implementation decisions

Map pod service account, SecretProviderClass namespace and provider-specific workload identity into the requested external secret. Mount permission and permission to sync a Kubernetes Secret can differ. A privileged operator changing the pod identity is setup authority, not an app-originated exploit; inspect whether an actual restricted workload can select another identity or resource.

## Operational method

Choose provider and authentication mode explicitly: node identity, pod identity and workload federation select different principals. Collect SecretProviderClass parameters, pod service account and the effective identity-selection path. A fixture that grants every pod the same fake node identity cannot establish workload isolation. Compare two synthetic secret identifiers under the same actual restricted workload identity and verify provider admission before treating a mounted path as secret exposure.

## Discriminating verification

Use a local provider stub with synthetic secrets; compare rightful pod/service-account mount and a foreign resource or provider-class substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A successful controller/admin mount does not show an unprivileged pod can read another secret.

## Repair acceptance

Bind provider configuration and external resource authority to the intended workload, verifying mount and rotation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://secrets-store-csi-driver.sigs.k8s.io/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
