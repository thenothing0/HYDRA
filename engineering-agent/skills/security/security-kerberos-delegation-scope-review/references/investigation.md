# Investigation: Kerberos delegation configuration and service-to-service identity scope

## Trace in the actual implementation

Trace which service identity may act for which user toward which target, separating ticket issuance from accepted protected operations.

## Implementation decisions

Distinguish unconstrained, traditional constrained and resource-based constrained delegation with actual account flags and service principals. A delegation setting is not proof the actor controls the delegating principal or can obtain a usable ticket. Trace the permitted service/identity transition from supplied configuration without capturing or replaying production tickets.

## Operational method

Map actual mode artifacts: unconstrained delegation uses the TRUSTED_FOR_DELEGATION account flag; traditional constrained delegation uses the service account msDS-AllowedToDelegateTo SPN list, with protocol-transition prerequisites such as TRUSTED_TO_AUTH_FOR_DELEGATION where applicable. Resource-based constrained delegation instead uses the target msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor. Do not impose one mode flag on every other mode. Retain protected/nondelegable-user restrictions, principal/SPN mapping and authority to edit the controlling object. Trace supplied configuration to KDC ticket issuance and final service authorization; a flag or ticket alone is not a protected action.

## Discriminating verification

Use owned lab principals and a harmless test service, or perform configuration-only analysis when ticket testing is outside scope.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A delegation flag or SPN is not demonstrated arbitrary domain access; protected-user constraints and target policy may stop the path.

## Repair acceptance

Limit delegation to intended services/users and retest legitimate service flows and forbidden target selection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
