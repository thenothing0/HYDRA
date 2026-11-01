# Investigation: OIDC front/back-channel logout and local session termination

## Trace in the actual implementation

Trace issuer/session identity from a logout message to exactly the intended local sessions. Inspect replay and whether a notification merely clears UI state.

## Implementation decisions

Back-channel logout validation and front-channel browser state are different paths. Resolve sid/sub and issuer/client binding before selecting sessions. Browser cookie restrictions may block front-channel effects; a local logout UI change is not evidence that a server session or refresh family ended.

## Operational method

Validate a back-channel logout token as its own token class: signature/context, required logout event, issuer/audience, time and sid/sub selection; reject a Logout Token containing any nonce claim, even with an otherwise valid signature/events object. A valid login ID token is not a Logout Token. Retain replay handling and the exact selected sessions. Compare an authentic synthetic logout token with an otherwise valid login ID token and a wrong-session token; UI logout alone proves no refresh-family revocation.

## Discriminating verification

Use two owned issuer sessions and local sessions; compare intended logout, wrong-issuer/session message and a harmless replay.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A changed login screen is not proof that a server session was revoked; global logout may be an intentional policy rather than overbroad binding.

## Repair acceptance

Validate logout issuer/context and revoke the correct sessions; retest retained unrelated sessions and intended termination.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://openid.net/specs/openid-connect-backchannel-1_0.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
