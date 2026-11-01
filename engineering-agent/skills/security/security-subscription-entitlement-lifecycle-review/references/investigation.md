# Investigation: Subscription state changes and actual product capability grants

## Trace in the actual implementation

Trace plan identity and payment state into server capability checks, including downgrade/cancellation and delayed webhook replay.

## Implementation decisions

Use the effective plan transition and documented grace period, not only a payment-provider event timestamp. Events may be delayed or out of order. Identify the protected server capability and whether a later authoritative event correctly reconciles it; a retained badge or invoice alone is not product access.

## Operational method

Record authoritative event identity/version, provider state and the entitlement reducer rule. Feed owned events in order, then deliver an older active event after a newer cancellation and observe which generation controls the protected capability. Do not order unrelated events solely by arrival timestamp. Grace periods and corrective reconciliation are product policy; a stale badge is not continued server entitlement.

## Discriminating verification

In an owned billing fixture compare an active entitled action with the same action after an effective downgrade or canceled synthetic subscription.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A retained badge or documented grace period is not a privilege bypass; show an action forbidden by the declared plan policy.

## Repair acceptance

Reconcile provider events and server entitlements, then verify allowed grace, downgrade and replay behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
