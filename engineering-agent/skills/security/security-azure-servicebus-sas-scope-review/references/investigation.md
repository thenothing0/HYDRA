# Investigation: Service Bus SAS policy scope and message operation authority

## Trace in the actual implementation

Determine which queue/topic operation the credential permits and whether a client-scoped token reaches another entity or management operation.

## Implementation decisions

Identify the namespace/entity resource URI and Listen, Send or Manage rights attached to the signing policy. A valid SAS token for one entity must not be assumed to authorize the entire namespace. Separate token issuance by an application from broker enforcement, and test receive versus send only with synthetic queues/topics in a supplied sandbox.

## Discriminating verification

Use an owned namespace fixture with synthetic messages; compare intended send/listen and a forbidden entity/operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A connection string label does not establish its permissions; management metadata is different from message contents.

## Repair acceptance

Issue entity/operation-scoped capabilities and validate consumer identity independently, then test renewal and restricted entities.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
