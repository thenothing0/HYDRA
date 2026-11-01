# Investigation: LDAP signing/channel-binding enforcement for directory authentication

## Trace in the actual implementation

Determine what authenticity/integrity properties the actual bind path enforces, distinguishing TLS peer validation from binding the authenticated session.

## Implementation decisions

Separate simple bind over TLS, SASL signing and TLS channel-binding requirements for the actual client/server combination. Signing policy and channel-binding policy cover different relay/tampering paths. A rejected unsigned bind is a useful specific control; it does not prove every TLS client validates the directory peer or supplies the required binding.

## Discriminating verification

Use an owned directory lab or configuration trace with synthetic accounts; compare a supported protected bind and a deliberately unsupported protection mode.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A listening LDAP port or successful anonymous metadata read is not credential relay or authenticated directory access.

## Repair acceptance

Enforce the required bind protections and verify normal directory clients and rejected weaker paths.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
