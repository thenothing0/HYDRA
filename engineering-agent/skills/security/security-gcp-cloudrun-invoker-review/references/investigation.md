# Investigation: Cloud Run invoker identity, audience and application resource authority

## Trace in the actual implementation

Resolve which layer authenticates invokers and which maps them to application tenants/resources. Keep public service admission separate from sensitive handler authorization.

## Implementation decisions

Distinguish service invoker IAM admission from application-level account/object checks. Verify the identity token audience expected by the configured service/custom audience and the actual ingress path. A publicly invokable service may be deliberate; the decisive issue is an unintended principal reaching protected application behavior, not the absence of an authentication prompt.

## Operational method

Record whether the invoker IAM check is disabled or whether allUsers has an invoker grant; these are different publication configurations. Identify which Authorization or X-Serverless-Authorization header the platform validates and what identity the application then verifies. In a supplied trace, separate platform admission from handler resource access. A public service intentionally returning public content remains the control; do not infer application authentication solely from the platform header being present.

## Discriminating verification

Use an owned service fixture and synthetic response; compare intended invoker/audience with another owned principal or audience.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A public URL or a platform 403 alone does not prove handler exposure or correct object authorization.

## Repair acceptance

Align service admission and handler identity/resource checks, preserving expected service-to-service invocation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/run/docs/authenticating/overview)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
