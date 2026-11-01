# Investigation: Search index/query authorization and stale document entitlements

## Trace in the actual implementation

Trace original document authority through index metadata into every returned hit/snippet/facet. Check whether caller-writable filters or stale ACLs substitute for current permission.

## Implementation decisions

Map source object permissions into indexed fields, query filters and post-fetch checks, including snippets, facets and suggestions. A stale index entry is not necessarily readable if a final entitlement check rejects it. Use a synthetic permission change and record the effective propagation contract; classify count/snippet leakage separately from full content disclosure.

## Discriminating verification

Use two owned synthetic documents and users; compare permitted search with a restricted document marker before/after entitlement removal.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A public title or aggregate count is not necessarily private content; establish the declared confidentiality of the observed signal.

## Repair acceptance

Bind index/query output to current entitlement and verify snippets, exports, facets and deletion paths relevant to the finding.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
