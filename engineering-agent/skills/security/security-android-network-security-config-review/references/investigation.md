# Investigation: Android effective cleartext and trust-anchor policy by build/domain

## Trace in the actual implementation

Resolve which domain/build policy the real client uses, including custom trust managers that bypass declarative configuration.

## Implementation decisions

Resolve build variant, target SDK, domain-config inheritance, debug overrides and the network stack actually making the request. Native or third-party clients may not honor the XML policy. A debug trust anchor is not a release weakness without release applicability; show effective cleartext/peer acceptance with an owned endpoint and the real client path.

## Discriminating verification

Use an emulator and owned local endpoint with synthetic data; compare expected TLS validation and an intentionally invalid test certificate.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A debug-only trust anchor is not a release flaw; an HTTP string unused by the application is not sensitive cleartext transmission.

## Repair acceptance

Apply correct release/domain trust policy and retest actual client validation and legitimate TLS.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/privacy-and-security/security-config)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
