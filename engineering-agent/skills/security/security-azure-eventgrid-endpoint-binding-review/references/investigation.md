# Investigation: Event Grid subscription validation and event-consumer authority

## Trace in the actual implementation

Separate proof of endpoint control from proof that delivered events originate from the intended topic/tenant. Trace fields used for privileged downstream actions.

## Implementation decisions

Endpoint validation establishes subscription delivery control; it does not make arbitrary future request bodies authentic. Identify the delivery schema and configured authentication mode, then trace verified subscription/source context into the consumer. A replayed legitimate event may be an idempotency issue, while an unsigned external body accepted as privileged input is a separate trust boundary.

## Operational method

For Event Grid event schema, identify the POST Microsoft.EventGrid.SubscriptionValidationEvent and its data.validationCode; the synchronous ownership response echoes that value as validationResponse. CloudEvents v1.0 instead uses the OPTIONS abuse-protection handshake with WebHook-Request-Origin and WebHook-Allowed-Origin; it does not use the Event Grid validation-event mechanism. Retain configured delivery authentication separately from this endpoint-control handshake. Compare the correct schema handshake and one mismatched mode, then inspect an authentic synthetic business event versus an untrusted body at the protected consumer; echoing a validation code is not event authenticity.

## Discriminating verification

Use owned endpoints and synthetic events; compare a valid subscription/delivery with a locally forged event bearing the same data fields.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Echoing a validation code or accepting a public webhook request is not a protected effect by itself.

## Repair acceptance

Authenticate delivery context and constrain action resources, preserving legitimate subscription validation and retries.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/event-grid/webhook-event-delivery)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.

- [Additional implementation reference](https://learn.microsoft.com/en-us/azure/event-grid/end-point-validation-event-grid-events-schema)

- [Additional implementation reference](https://learn.microsoft.com/en-us/azure/event-grid/end-point-validation-cloud-events-schema)
