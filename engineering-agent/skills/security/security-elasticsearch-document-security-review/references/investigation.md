# Investigation: Elasticsearch index/alias and document-level authorization

## Trace in the actual implementation

Trace index/alias resolution and the actual security filter applied to the requested operation, including owned search/export paths.

## Implementation decisions

Determine how multiple roles combine and whether document/field restrictions apply to the actual API and license/configuration. An alias is not inherently an authorization boundary. Compare search, direct document and alternate permitted paths with owned markers; an aggregation count or a metadata field can be a distinct limited disclosure rather than full document access.

## Operational method

Compute the effective same-index role combination: DLS grants combine by OR, and a role granting that index without DLS can remove the document restriction; field permissions combine by union. These read restrictions are not a general write policy. Retain every applicable role and index/alias match, then compare two synthetic documents/fields under the merged roles. A correct filtered search under one isolated role does not establish the actual user restriction.

## Discriminating verification

Use synthetic documents for two owned tenants and compare an entitled query with a known foreign-document request through a relevant supported API.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An index name or intentionally shared aggregate is not a document leak; admin query success does not establish a user bypass.

## Repair acceptance

Bind effective index/document policy across intended APIs and retest authorized searches and foreign markers.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level)
- [Additional implementation reference](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
