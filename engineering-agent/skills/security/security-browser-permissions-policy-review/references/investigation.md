# Investigation: Delegated browser capabilities across embeds using effective Permissions Policy

## Trace in the actual implementation

Identify the exact browser feature and how ancestor policy plus frame delegation constrains it. Separate user permission, secure-context requirements and policy denial.

## Implementation decisions

A parent policy denying a feature cannot be broadened merely by a permissive iframe allow attribute. Record the frame origin, sandbox and user grant separately. Querying a permission status is not obtaining protected sensor data; verify the particular API operation and its policy-denied outcome.

## Discriminating verification

In owned origins invoke only a synthetic or non-sensitive feature check with intended and untrusted embeds; record policy-denied versus user-denied outcomes.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An absent policy or permission prompt does not prove access to camera/location or any actual sensitive resource.

## Repair acceptance

Limit delegation to intended origins and retest allowed embedding and policy rejection without changing user grants to manufacture a result.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Permissions_Policy)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
