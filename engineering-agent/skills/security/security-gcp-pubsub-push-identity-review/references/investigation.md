# Investigation: Pub/Sub authenticated push identity and subscription binding

## Trace in the actual implementation

Trace verified push identity into the trusted subscription/tenant and downstream action. A payload subscription field is not independently authenticated.

## Implementation decisions

Validate the push token issuer, audience and intended service-account identity under the configured endpoint. The JSON subscription field is not independently authenticated merely because it appears in the body. An authentic push identity shared across subscriptions may still need application resource binding; a token replay without an unauthorized consumer effect remains a narrower observation.

## Discriminating verification

Use an owned endpoint/local push fixture; compare expected service-account/audience with a valid token for another owned sender or a payload substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An HTTP acknowledgment or JSON event acceptance does not prove a protected action; inspect the synthetic effect.

## Repair acceptance

Bind verified push identity/audience and event scope, then verify legitimate delivery, retries and rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
