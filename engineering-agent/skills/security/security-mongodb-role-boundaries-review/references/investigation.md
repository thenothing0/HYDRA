# Investigation: MongoDB database/collection actions and delegated role authority

## Trace in the actual implementation

Resolve the actual principal and action/resource grant, including whether a wrapper supplies privileged credentials for caller-selected namespaces.

## Implementation decisions

Evaluate inherited roles with database and collection resource scope, including anyResource or cluster actions. Authentication database is not necessarily the database being accessed. A driver connection succeeding proves login only; record the exact collection operation allowed to the restricted principal and do not infer write, admin or cross-database rights from a read.

## Operational method

Identify self-hosted versus Atlas role definitions and the effective deployment API before interpreting familiar role names. Expand inherited privileges into action/resource pairs and inspect role-grant/user-administration authority separately from collection reads. Use supplied users/roles definitions and one owned collection operation; a permitted role-administration action can create a distinct delegation path, but do not grant a production role to demonstrate it.

## Discriminating verification

Use a local database with two owned namespaces and synthetic documents; compare permitted action and one forbidden collection/role operation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Connection success or database-name discovery is not document-read or administrative authority.

## Repair acceptance

Limit effective roles and wrapper namespace selection, testing legitimate queries and restricted resources.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.mongodb.com/docs/manual/core/authorization/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
