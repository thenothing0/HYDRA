# Investigation: SCIM connector tenant, account and group-membership authority

## Trace in the actual implementation

Trace external identifiers and connector authority into local account/group operations, especially replace/remove membership and disabled-user handling.

## Implementation decisions

PATCH add/remove/replace and bulk semantics need the actual schema/path interpretation, especially group members and user active state. A connector may legitimately administer all users in its own tenant. Test cross-tenant mapping, immutable identity and deprovisioned-session effects as separate assertions.

## Operational method

Retain the ordered PATCH operation list and filtered path interpretation, especially group members and active state. Distinguish connector externalId lookup from server-assigned id and inspect which tenant namespace each uses. Compare the before/after synthetic membership set, not only the final status code; a valid same-tenant administrative connector operation remains a positive control.

## Discriminating verification

Use two owned tenants and synthetic users/groups; compare the rightful connector with cross-tenant identifier or PATCH membership substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An externalId collision is not account compromise unless it selects or alters the wrong local principal.

## Repair acceptance

Bind connectors and operations to tenant/principal policy and verify create/update/deactivate plus unrelated tenant preservation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc7644)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
