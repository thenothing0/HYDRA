# Investigation: AD CS certificate template enrollment and identity authority

## Trace in the actual implementation

Determine which low-privilege principal can enroll or modify a template and what identity/purpose a resulting certificate would represent.

## Implementation decisions

Evaluate template enrollment rights, subject/SAN control, issuance requirements, EKUs and CA policy together. A permissive-looking template alone does not establish a usable authentication certificate. Use exported configuration or an isolated lab to trace the exact claimed principal and relying service; do not enroll certificates impersonating real directory users.

## Operational method

Retain CA/DC build and patch level, template issuance/enrollment settings, certificate SID/strong mapping evidence and the actual relying authentication protocol. A SAN selected by a caller is not enough to decide accepted identity under current strong-mapping enforcement. Compare a deliberately mapped synthetic identity with a mapping-mismatched certificate in supplied traces or an isolated directory lab; certificate issuance, successful mapping and final service authorization are separate necessary edges. Do not request impersonation certificates for real principals.

## Discriminating verification

Use an owned lab CA or configuration proof with synthetic identities; compare intended enrollment and an out-of-policy subject/purpose request.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A risky-looking template flag alone does not establish effective enrollment or certificate-based authentication to a protected service.

## Repair acceptance

Constrain enrollment/template authority and issuance identity, verifying intended certificate workflows and denied impersonation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)
- [Additional implementation reference](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
