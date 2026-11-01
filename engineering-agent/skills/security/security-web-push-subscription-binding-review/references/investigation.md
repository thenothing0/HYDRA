# Investigation: Web Push subscription ownership and delivery authorization

## Trace in the actual implementation

Determine who can attach, replace or delete a subscription and which user data the sender chooses independently of client-supplied recipient identifiers.

## Implementation decisions

A PushSubscription includes an endpoint and encryption material, while a public application-server key has a different role. Verify which identity can update a stored subscription and which user payload is selected for delivery. Successful endpoint registration is not proof the provider accepted or delivered sensitive content.

## Operational method

Track endpoint/encryption material ownership across logout and account switch in the same browser profile. Record the authenticated server registration/update caller, previous owner, new owner and payload recipient selected by the sender. A subscription endpoint being accepted is not delivery proof. Use synthetic notifications and verify an old account marker is not sent to a subscription newly bound to another account unless explicitly permitted.

## Discriminating verification

Use owned subscriptions or a local push stub; compare rightful registration with another owned user/device binding and inspect a harmless delivered marker.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A subscription endpoint is not a login token; public VAPID keys or a successful registration status alone prove no message leakage.

## Repair acceptance

Bind registration and delivery to authenticated ownership, preserving multi-device lifecycle and logout removal.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc8030)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
