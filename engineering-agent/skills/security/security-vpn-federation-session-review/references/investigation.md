# Investigation: VPN gateway identity/posture mapping into tunnel and resource authority

## Trace in the actual implementation

Trace issuer authentication context into VPN authorization and session refresh/reconnect, including local fallback identities.

## Implementation decisions

Map federated assertion assurance to the gateway session, device posture and resource policy. The IdP session and the VPN tunnel can have different documented lifetimes. A valid SSO response alone does not demonstrate internal network access; confirm only the owned permitted service path and classify revocation delay against the declared contract.

## Operational method

Specialize in one supplied gateway/protocol profile: assertion/token validation, mapped local VPN role, device/posture identity, tunnel issuance and permitted resource ACL. Compare the IdP identity/assurance with the actual tunnel/session record and one owned service access result, including reassessment on reconnect or posture change where the contract requires it. A generic SAML fixture cannot define gateway enforcement; absent gateway mapping is an explicit blocker, not proof of internal access.

## Discriminating verification

Using supplied gateway mappings or an owned gateway fixture, trace one synthetic federation identity and posture result into local VPN role, tunnel issuance and one permitted resource. Compare an assurance/posture mismatch or revoked reconnect under the actual profile.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A successful IdP login or missing UI MFA prompt does not prove gateway assurance downgrade; the assertion/session may already carry required assurance.

## Repair acceptance

Bind federation context and gateway session policy, verifying intended reconnect and required assurance.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
