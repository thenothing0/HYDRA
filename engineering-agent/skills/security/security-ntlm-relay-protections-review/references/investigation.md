# Investigation: NTLM service binding, signing and relay-resistance configuration

## Trace in the actual implementation

Identify an actual trusted-authentication relay path and target binding requirements from configuration. Keep credential coercion/relay execution outside ordinary review.

## Implementation decisions

Branch by receiving protocol: signing, extended protection/channel binding and service configuration are not interchangeable defenses. The absence of one setting does not prove a relay chain without an available authentication source and accepted destination. Use configuration and owned protocol fixtures; do not coerce production users or collect NTLM exchanges.

## Operational method

Build a receiving-protocol matrix for the actual path: SMB signing, LDAP signing/channel binding and HTTP extended protection/TLS termination are different checks. Record server enforcement, client support and whether a proxy terminates or forwards the authenticated channel. An absent setting is a lead until a feasible source/destination and accepted operation are shown. Use configuration and isolated owned fixtures; no production authentication coercion or relay is required.

## Discriminating verification

Use only an owned isolated authentication fixture or supplied configuration evidence to compare enforced and absent target binding.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

NTLM enabled or signing optional at one host is not proof of an exploitable relay chain with a suitable source and target.

## Repair acceptance

Enforce appropriate channel/service binding or remove the unnecessary path, verifying supported legitimate clients.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
