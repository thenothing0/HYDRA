# Investigation: Firebase custom-token minting and caller-to-UID/claims binding

## Trace in the actual implementation

Trace how an authenticated application caller can select Firebase uid or privileged claims. Validate upstream identity before the trusted minting operation.

## Implementation decisions

The issuer must derive UID and privileged claims from an authorized identity mapping, not accept them as caller assertions. Custom tokens are exchanged for Firebase ID tokens; do not confuse their audiences and validation roles. A server/Admin SDK bypassing client rules is expected unless an untrusted caller can exercise that server authority.

## Discriminating verification

Use an emulator/local issuer fixture with two synthetic identities; compare rightful token identity and a caller-selected foreign uid/role.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Public Firebase configuration is not minting authority; an unused custom claim is not a demonstrated privilege grant.

## Repair acceptance

Bind minting to verified identity and permitted claims, then test final rules/consumer authority and legitimate sign-in.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://firebase.google.com/docs/auth/admin/create-custom-tokens)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
