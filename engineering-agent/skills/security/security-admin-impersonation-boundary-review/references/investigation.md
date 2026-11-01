# Investigation: Administrative impersonation scope and session authority

## Trace in the actual implementation

Trace which privileges come from the operator and which from the impersonated subject. Inspect escape/endpoints that accidentally retain administrative authority.

## Implementation decisions

Establish whether actor and subject authorities intersect or an explicit support capability set applies. Inspect exit, nested impersonation and session refresh separately. Audit attribution helps accountability but is not the authorization gate; intended operator-only access is not a subject-originated escalation.

## Discriminating verification

Use owned operator and test subject accounts with synthetic resources; compare intended support actions and an explicitly forbidden administrative or subject action.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An approved operator viewing a test account is expected; an audit label or UI banner is not the enforcement control.

## Repair acceptance

Enforce explicit impersonation capabilities and lifecycle, then verify exit, revocation and audit attribution.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
