# Investigation: SQL Server execution context, ownership chains and delegated modules

## Trace in the actual implementation

Follow caller execution into modules and cross-database operations using the actual effective principal and ownership path.

## Implementation decisions

Resolve EXECUTE AS CALLER/OWNER/principal, ownership chaining, module signing and cross-database trust separately. Permission to execute a module can deliberately delegate its fixed action. Evaluate whether its actual resource/projection violates the caller policy, whether the module is fixed or influenced by lower-trust parameters/editing; do not require editable input before reviewing fixed-module data disclosure.

## Operational method

A fixed module can expose forbidden tenant rows even when its inputs and definition cannot be edited; inspect its returned projection and actual caller policy. Separate ordinary ownership chaining from dynamic SQL, which breaks that chain, EXECUTE AS identity substitution and certificate-signing additive permissions. For cross-database access retain trust/signature/user mappings on both databases and whether the module was re-signed after changes. Compare one restricted caller result with the same caller direct-query denial; this may establish intended narrow delegation or an overbroad fixed module.

## Discriminating verification

Use an isolated SQL Server fixture with synthetic tables and two owned principals; compare approved module use and an out-of-policy object access.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A module that legitimately elevates for a narrowly defined operation is not arbitrary privilege escalation.

## Repair acceptance

Constrain module inputs/context and cross-database delegation, preserving the intended stored operation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql)
- [Additional implementation reference](https://learn.microsoft.com/en-us/sql/connect/ado-net/sql/writing-secure-dynamic-sql?view=sql-server-ver17)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
