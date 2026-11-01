# Investigation: RabbitMQ vhost/exchange/queue and routing-key authorization

## Trace in the actual implementation

Resolve configure/write/read authority and whether routing/bindings bridge data across intended tenant vhosts or exchanges.

## Implementation decisions

Evaluate configure, write and read regex permissions separately within the selected vhost, plus topic permissions when applicable. Exchange publication and queue consumption have different resources and routing decisions. A binding can connect otherwise permitted resources, so inspect its authority without assuming a successful connection grants access to all messages.

## Operational method

Use the protocol operation-to-resource map: for AMQP queue.bind, evaluate write on the queue and read on the exchange, separately from basic.publish and basic.consume checks. Include topic routing-key permissions where used. Retain vhost, effective user/backend and whether a connection caches permissions; after a grant change compare an existing connection with a fresh one. A generic successful publish cannot validate binding or consumer authority.

## Discriminating verification

Use an isolated broker with two owned tenants and synthetic messages; compare intended publish/consume and one forbidden binding or routing key.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An open AMQP connection or queue name is not message access; public shared exchanges may be intentional.

## Repair acceptance

Constrain vhost/resource/routing authority and retest intended bindings, delivery and cross-tenant denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rabbitmq.com/docs/access-control)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
