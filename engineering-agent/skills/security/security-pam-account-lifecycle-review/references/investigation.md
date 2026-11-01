# Investigation: Privileged access management checkout, approval and revocation binding

## Trace in the actual implementation

Trace who can request which managed account and whether approval remains bound to resource, purpose, operator and time during use.

## Implementation decisions

Separate approval, credential checkout, brokered session and actual privileged account lifetime. Closing a ticket may not promise immediate termination of every active session. Trace the declared expiry/revocation semantics and whether the same actor retains a prohibited capability; an audit event proves recording, not termination or least privilege.

## Operational method

Identify credential-disclosing checkout versus broker-only session access before selecting the revocation oracle. Retain account/approval binding, credential version, checkout expiry, rotation event and any reconnect capability. Compare a legitimate owned checkout/session with a stale checkout after the declared expiry/rotation rule. Closing a ticket does not universally terminate a tunnel or erase a disclosed password; the product contract decides which final capability should cease.

## Discriminating verification

Use a local PAM stub and synthetic credential/session capability; compare approved checkout and wrong-account/stale-approval use.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Viewing a managed account name is not credential access; an approved privileged session is expected within its declared scope.

## Repair acceptance

Bind approval and brokered use to current authority, verifying rotation/revocation and intended emergency access.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
