# Investigation: KMS decrypt/data-key authority across encryption contexts and services

## Trace in the actual implementation

Resolve effective KMS authority and whether trusted encryption context or ViaService constraints bind the intended tenant/workload. Treat encryption context as authenticated metadata, not secret data.

## Implementation decisions

Encryption context is authenticated additional data, not encrypted secret storage. Follow the exact context supplied to KMS and conditions in both key and identity policies, including grants and service-mediated calls. A caller able to choose a tenant context must still be authorized to use that tenant; mere knowledge of the context is not entitlement.

## Operational method

Start from key type and exact API: encryption context applies to supported symmetric encryption operations, not every asymmetric or HMAC operation. Record the literal map sent to Encrypt/Decrypt and the condition/grant used. Distinguish EncryptionContextEquals from EncryptionContextSubset constraints and compare the caller-supplied tenant map with the policy-expected map. A local cryptographic context mismatch is not evidence that IAM separates tenants; inspect the grant/policy path independently.

## Discriminating verification

Use an owned test key and synthetic ciphertext locally/in an authorized sandbox; compare rightful context and principal with a mismatched tenant context.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

The ability to invoke an SDK or read a key ARN is not decryption authority; cryptographic rejection alone does not test IAM separation.

## Repair acceptance

Constrain principal/service/context authorization and verify legitimate decrypt plus cross-context denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
