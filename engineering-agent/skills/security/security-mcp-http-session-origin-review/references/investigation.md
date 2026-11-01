# Investigation: MCP HTTP transport revision, origin and request/stream authority binding

## Trace in the actual implementation

Select the implemented HTTP transport profile, then follow validated request identity and transport metadata into tool execution and the correct response stream. Apply session ownership only to a session-bearing legacy profile.

## Implementation decisions

Separate legacy session-bearing Streamable HTTP from the stateless 2026-07-28 revision before interpreting transport state. A session identifier is never a substitute for request authentication; a modern implementation need not create one. Validate a present Origin independently from legitimate nonbrowser absence and resolve mirrored metadata under the applicable profile.

## Operational method

Select the implemented protocol revision before testing. Legacy Streamable HTTP revisions 2025-03-26 through 2025-11-25 can have protocol sessions; review authenticated session ownership and stream routing there. Revision2026-07-28 removes protocol sessions and the standalone GET stream: do not demand a session or treat an ignored Mcp-Session-Id as bypass. For that profile compare MCP-Protocol-Version and mirrored method/name/annotated-parameter headers with body metadata and request fields under its validation rules. Each request still needs applicable authentication and present-Origin validation; absent Origin can be a legitimate non-browser case.

## Discriminating verification

Use an owned mock for the selected profile: compare authorized request, absent-Origin authenticated nonbrowser request and invalid present Origin. For legacy sessions compare wrong-owner routing; for 2026-07-28 compare mirrored-header/body mismatch and per-request stream ownership.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An ignored legacy session header on a stateless modern profile, an authenticated nonbrowser request without Origin or absence of standalone GET streams is not itself a bypass; require a violated applicable authority rule.

## Repair acceptance

Enforce the selected revision request/origin/identity and stream binding rules, then retest legitimate requests and the specific forbidden context without imposing legacy session mechanics on the modern profile.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Additional implementation reference](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
