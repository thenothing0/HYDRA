# Investigation: MCP OAuth registration profiles and client-metadata-to-consent binding

## Trace in the actual implementation

Trace a client identity/redirect through registration to granted resource authority, including reuse of client metadata across protected MCP resources.

## Implementation decisions

Distinguish registration metadata from user consent and from authorization-server identity. Dynamic registration can be a supported public-client flow. Pin the redirect/client relationship and broker transaction so an attacker client cannot reuse another client consent; a new valid client record by itself is not a successful impersonation or token disclosure.

## Operational method

Identify the actual registration profile first: pre-registered clients, dynamic registration or supported client-metadata documents are different trust paths. Retain client metadata provenance, redirect selection and the exact client identity displayed/recorded at consent. Compare a legitimate client update with an untrusted metadata/redirect change; open registration alone is expected under some profiles. Generic wrong-resource token validation remains the MCP authorization workflow.

## Discriminating verification

In the chosen registration profile, retain registered metadata and consent transaction for two owned clients. Compare legitimate creation/update with a changed redirect or metadata provenance and inspect the client identity receiving the resulting grant.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Dynamic registration can be intentional; a client ID alone grants no user/resource permission.

## Repair acceptance

Bind registration and consent to the intended client/resource and preserve legitimate compatible clients.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://modelcontextprotocol.io/specification/latest/basic/authorization)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
