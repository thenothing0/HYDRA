# Investigation: Google Cloud Storage signed URL issuance and signer delegation

## Trace in the actual implementation

Trace caller resource selection into the signed capability and separate permission to sign from entitlement to the requested object.

## Implementation decisions

Separate the application caller from the service account that signs the capability, including remote signBlob delegation. Bind method, object, headers and effective lifetime to the caller permission. Signature validity does not establish caller entitlement, and a public object returning the same bytes cannot demonstrate a private-object disclosure through the issuer.

## Operational method

Separate the caller permitted to invoke iam.serviceAccounts.signBlob on the signer account from that signer account authorization to perform the storage operation. Retain the application caller policy, signing-account resource and redacted canonical request. Local key signing proves neither remote impersonation authority nor object redemption. The control denies an unauthorized caller before signing, while an intentionally authorized recipient can redeem only the intended method/object capability.

## Discriminating verification

Use two owned synthetic objects and compare rightful URL issuance with a foreign object/generation/method request.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Bearer use of a deliberately shared signed URL is expected; the missing boundary may be at application issuance.

## Repair acceptance

Authorize resource/method/lifetime before signing and retest intended sharing and unauthorized issuance.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/storage/docs/access-control/signed-urls)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
