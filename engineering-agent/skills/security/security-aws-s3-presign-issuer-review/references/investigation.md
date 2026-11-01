# Investigation: S3 SigV4 issued capabilities: signed fields, signer lifetime and object version

## Trace in the actual implementation

Trace the caller-selected resource and operation to the signer identity and effective capability. Determine whether the requester is authorized for that exact object before signing.

## Implementation decisions

Evaluate the caller policy at the signing application separately from the signing principal permissions. The bearer URL may intentionally permit an unauthenticated recipient. Bind operation, bucket, key, required headers and expiry; inspect whether a later object replacement changes what a still-valid download URL serves. A locally generated signature does not prove the application grants it to a restricted caller.

## Operational method

Evaluate the actual SigV4 capability, not just issuer entitlement: method, canonical object key, optional versionId, signed headers, signer credential type and credential expiry. A temporary signer session can expire before X-Amz-Expires; a version-bound GET differs from a mutable unversioned key. For upload issuance, distinguish presigned PUT headers from POST policy conditions and check the stored object/version the application later consumes. Preserve the application request and redacted canonical signing inputs; a valid signature or successful public-object read does not demonstrate another caller may obtain the capability. Route general bucket publication to the S3 access-policy workflow.

## Discriminating verification

Inspect a redacted owned SigV4 signing request with temporary signer expiry, signed headers and optional versionId. Compare intended capability with altered method/key/header/version or expiry assumptions using offline canonical inputs; claim redemption only if an authorized fixture actually observes it.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A transferable presigned URL is intentional. Its mere use by its bearer is not a bypass of the signer endpoint.

## Repair acceptance

Authorize requester/resource/operation before signing and retest scope, expiry and intended downloads.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
