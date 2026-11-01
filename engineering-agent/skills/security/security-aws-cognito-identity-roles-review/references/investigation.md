# Investigation: Cognito identity-pool role selection and effective workload authority

## Trace in the actual implementation

Follow a presented identity into selected role and resulting session restrictions. Distinguish authentication success from excessive AWS permissions granted by that role.

## Implementation decisions

Identify identity pools separately from user-pool login. Determine whether authenticated, unauthenticated or claim-mapped roles are selected and what the resulting STS session actually permits. A client-visible pool ID is not a secret. Evaluate audience/subject/authentication-state trust and ambiguous role rules before interpreting a successful identity or credential issuance as excess privilege.

## Operational method

Collect identity-pool aud and amr conditions from the role trust policy, the login provider claim mapping, role-mapping rules, ambiguous-role resolution and any allowed CustomRoleArn choice. Follow the selected role into the resulting session permissions. Use two synthetic claim sets differing in the decisive rule input, with an unauthenticated claim-state control; an identity ID or successful login is not proof that the privileged role was selected.

## Discriminating verification

Use an owned identity pool/test roles with harmless resources; compare intended identity class with a controlled provider/role-mapping variation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An unauthenticated identity ID can be intended; no sensitive AWS action is proved by obtaining it alone.

## Repair acceptance

Constrain role selection/trust and effective permissions, verifying intended guest and authenticated capabilities.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
