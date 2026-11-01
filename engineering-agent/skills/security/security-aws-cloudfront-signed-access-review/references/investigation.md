# Investigation: CloudFront signed URL/cookie policy and content publication boundary

## Trace in the actual implementation

Resolve the exact resource/time/IP policy and issuance authority, then determine whether alternate distribution/origin paths bypass the intended private delivery.

## Implementation decisions

Inspect the actual distribution behavior and origin access path, not only a signed cookie. A custom policy can intentionally cover a path wildcard, while a direct public origin may bypass the distribution entirely. Separate URL expiry from an already-started transfer and signed access from per-customer entitlement; use owned marker objects for both paths.

## Discriminating verification

Use owned synthetic objects/distribution paths and compare allowed signed delivery with an unauthorized path or expired capability.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A cached object intentionally published publicly is not a signature bypass; a valid bearer sharing a capability follows its declared model.

## Repair acceptance

Bind signer scope and origin protection, then verify authorized delivery and rejected alternate paths.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PrivateContent.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
