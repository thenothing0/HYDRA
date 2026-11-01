# Investigation: EventBridge producer identity, routing and consumer trust

## Trace in the actual implementation

Determine whether untrusted producers can set fields the consumer treats as an authenticated tenant or action instruction.

## Implementation decisions

An event detail field claiming a tenant or user is application data, not the caller identity authenticated by the bus. Evaluate PutEvents admission, routing rule scope and consumer validation independently. Service-originated events and custom producers have different provenance; a rule match alone does not demonstrate that a protected consumer trusts a forged identity.

## Operational method

Inspect PutEvents rights separately from PutRule/PutTargets and rule-update authority. Retain producer principal, source bus, selected rule and target ARN for the same synthetic event. A rule writer can redirect an otherwise authentic event; that is different from a producer forging detail fields. Verify the consumer action and intended destination with a local event-routing stub or supplied trace, without publishing real notifications.

## Discriminating verification

Use an owned bus or local event fixture with inert markers; compare intended producer events and a controlled spoofed authority field.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Publishing to a public intake bus can be intentional; a rule match alone is not a privileged consumer effect.

## Repair acceptance

Authenticate producer context and validate consumer authority, then retest rightful events and spoofed-field rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
