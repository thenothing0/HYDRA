# Investigation: SQS producer/consumer authority and message-driven operations

## Trace in the actual implementation

Trace who can send, receive, delete or redrive messages and whether message body/attributes grant downstream authority.

## Implementation decisions

Separate send, receive, delete and queue-policy administration. Message attributes are producer-controlled unless another verified envelope binds them. Inspect visibility timeout and redelivery as normal delivery behavior, then check consumer idempotency/authority at the final action. Receiving a test message proves read access only to the tested queue and principal.

## Operational method

For SNS/EventBridge/service-to-queue delivery, inspect the queue resource-policy principal and applicable aws:SourceArn/aws:SourceAccount constraints. Match the exact source rather than accepting a payload source label. If SSE-KMS applies, keep KMS denial distinct from queue policy denial. The local fixture should model queue admission before consumer processing and use one source-allowed and one source-mismatched marker; no receive/list access to unrelated queues is needed.

## Discriminating verification

Use a small owned queue or local consumer with synthetic messages; compare rightful producer processing and an untrusted actor/authority field.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A visible queue URL is not queue access; authorized message submission alone is not application privilege escalation.

## Repair acceptance

Constrain queue operations and independently validate the consumer action/resource policy, including redrive.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-iam.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
