# Investigation: MCP tool metadata provenance and capability-change handling

## Trace in the actual implementation

Follow a metadata update into tool selection and actual granted actions. Treat descriptions as external data rather than a source of user authorization.

## Implementation decisions

Tool descriptions and schemas originate at a server with a particular trust level. A text change is not itself an authority grant unless it influences selection or arguments beyond user authorization. Bind approved capability identity to the actual called server/tool/version; compare metadata drift with a real changed operation in a local mock server.

## Operational method

Record the server/connection identity and actual tool name or broker-mapped identifier; do not invent a universally available immutable version field. Distinguish text-only description drift from changed input schema, annotations and the capability executed. Compare the approval object with the resolved server/tool/action at call time, including name collisions across servers. Pinning a description hash is not proof that the server implementation or downstream operation stayed unchanged.

## Discriminating verification

Use a local synthetic MCP server that changes a harmless tool description/schema; compare intended action and an unrelated suggested operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Hostile metadata text alone is not compromise; show a selected/executed unauthorized fixture action or approval mismatch.

## Repair acceptance

Pin/verify server capability provenance where needed and enforce action authority independently of descriptive text.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://modelcontextprotocol.io/specification/latest/server/tools)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
