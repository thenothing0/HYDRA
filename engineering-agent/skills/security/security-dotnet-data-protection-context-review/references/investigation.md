# Investigation: ASP.NET Core Data Protection key-ring and purpose isolation

## Trace in the actual implementation

Trace which applications/tenants share keys and purposes and whether one protected payload is accepted in another authorization context.

## Implementation decisions

Shared keys and application names can deliberately enable SSO. Compare intended security domains, application discriminator and the full purpose chain, plus key-ring read/write authority. Unprotect success alone is not an authorization grant: verify how the consumer interprets tenant, identity and purpose before asserting that another application can impersonate a protected user.

## Discriminating verification

Use two local owned apps with synthetic protected tokens; compare intended unprotect and a cross-app/purpose attempt.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Sharing a key ring can be intentional for a single security boundary; successful decryption is not a privilege grant unless the consumer accepts the payload context.

## Repair acceptance

Separate key access/purposes according to the intended boundary and retest legitimate migration and token use.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
