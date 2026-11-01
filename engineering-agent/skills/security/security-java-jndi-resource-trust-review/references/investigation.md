# Investigation: Java JNDI lookup authority and external object/resource handling

## Trace in the actual implementation

Follow lower-trust names into reachable naming providers and determine which local/network/deserialization capabilities the configured runtime permits.

## Implementation decisions

Resolve the actual JDK/provider version and configured factories, not historical default assumptions. A lookup URL can select a resource or object factory without enabling remote code loading. Trace caller control into the installed provider and downstream consumer; use an inert local provider stub instead of running a gadget or contacting an external naming server.

## Operational method

Resolve installed JDK/provider and the actual naming URL, ObjectFactory selection and returned-object consumer. Inspect effective object-factory/deserialization filters, including jdk.jndi.object.factoriesFilter where supported, and provider-specific settings; obsolete remote-codebase assumptions are not universal current behavior. An inert naming stub proves only lookup reachability. Require actual configured resolution or complete source evidence before claiming object construction, without executing gadgets or changing trust switches.

## Discriminating verification

Use a local inert naming stub or source-only complete trace; do not serve object factories or execution payloads to production.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A JNDI string or affected library name is not reachable code execution; version/configuration and consumer behavior matter.

## Repair acceptance

Constrain lookup sources/providers and object handling, preserving intended naming resources.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.oracle.com/javase/jndi/tutorial/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
