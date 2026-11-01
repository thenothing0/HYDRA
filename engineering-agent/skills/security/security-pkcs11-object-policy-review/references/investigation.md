# Investigation: PKCS#11 object attributes, sessions and permitted key operations

## Trace in the actual implementation

Trace lower-trust templates/handles into key creation, wrapping or use and determine whether operation attributes reflect the intended key purpose.

## Implementation decisions

Inspect session role, object class and CKA_SENSITIVE/EXTRACTABLE plus permitted usage/mechanisms; historical ALWAYS_SENSITIVE/NEVER_EXTRACTABLE attributes describe lifecycle constraints. Trusted wrapping and object templates can change effective policy. Software-token tests establish that implementation only, not physical HSM enforcement, and a permitted signature operation does not prove raw key extraction.

## Operational method

Review C_CreateObject, C_CopyObject and C_SetAttributeValue separately. Retain CKA_COPYABLE/MODIFIABLE and the allowed transitions for sensitivity/extractability under the selected specification and module; making a key more restrictive differs from relaxing it, and historical attributes track lifecycle. Use disposable software-token keys only when that implementation is the test target. Compare allowed attribute changes with a denied relaxation; a signature operation is neither copying nor raw extraction.

## Discriminating verification

Use a local software token with synthetic keys and a reviewed operation sequence; compare allowed use and a policy-forbidden template/operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A key handle or token login is not export authority; do not extrapolate a software-token behavior to an untested HSM.

## Repair acceptance

Constrain object templates and role operations, testing legitimate key use, wrapping rules and lifecycle.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
