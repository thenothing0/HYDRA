# Investigation: ClickHouse effective row policies, roles and alternate data paths

## Trace in the actual implementation

Trace which policies apply to the selected table/query identity and whether a permitted alternate engine/view path bypasses the intended tenant restriction.

## Implementation decisions

Evaluate active roles and permissive/restrictive policy composition for the installed version and table operation. SELECT row policy is not a universal write or external-table guard. A user with unrestricted alternative access may intentionally bypass the filtered view; distinguish an application boundary from a privileged DBA role.

## Operational method

Expand applicable roles and policy expressions: permissive policies combine as OR and restrictive policies constrain the result with AND. Resolve deployed-version/settings behavior when no policy applies, rather than assuming a universal default. Record the actual table operation and alternate view/table functions. Compare a mixed-tenant owned dataset under one role and the effective role set; SELECT filtering alone does not establish write or external-source confinement.

## Discriminating verification

Use isolated synthetic tenant rows with an ordinary application identity; compare entitled query and one reachable alternate path.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A superuser seeing all rows or an unused table-function name is not an application-user bypass.

## Repair acceptance

Apply the intended policy to effective data paths and test legitimate analytics and foreign-row denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://clickhouse.com/docs/sql-reference/statements/create/row-policy)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
