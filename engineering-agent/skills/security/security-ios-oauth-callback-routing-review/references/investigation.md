# Investigation: iOS OAuth callback routing and authorization-transaction binding

## Trace in the actual implementation

Trace OS-delivered callback fields into the exact pending client/account transaction and token exchange, distinguishing routing from session binding.

## Implementation decisions

Match the registered callback scheme/universal link, state and PKCE to the initiating app transaction. ASWebAuthenticationSession handling can differ from a general deep-link route. An unrelated app registering the same scheme does not prove code redemption; the code, verifier and session must reach an unauthorized consumer in the supplied local model.

## Operational method

Choose the actual callback mechanism, such as ASWebAuthenticationSession matching versus a general custom-scheme/universal-link handler. Retain the initiating session/transaction, expected callback, state/PKCE context and cancellation/retry mapping. Compare two concurrent owned sign-ins and a callback arriving after cancellation. A callback reaching the app does not prove the wrong local transaction redeemed the code; bind the final session creation result.

## Discriminating verification

Use owned client/issuer fixtures and two local login transactions; compare intended callback with a swapped transaction or wrong callback origin.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A custom scheme is not automatically exploitable if PKCE/transaction validation stops code use; an intercepted route alone does not prove token theft.

## Repair acceptance

Bind routing and pending authorization state, preserving approved browser-to-app and cross-device behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
