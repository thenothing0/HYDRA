# Investigation: Backup/restore ownership across tenant and environment transitions

## Trace in the actual implementation

Trace who can select a backup and where its contents become readable after restore, including tenant IDs retained or rewritten by the application.

## Implementation decisions

Bind snapshot owner, environment, encryption identity and target tenant through restore and import. An authorized infrastructure operator may intentionally restore across environments; the issue is a restricted tenant selecting another tenant snapshot or receiving its data. Use tiny local backup fixtures and keep privileged snapshot creation separate from attacker-controlled restore selection.

## Operational method

Retain the restore mapping for tenant/principal IDs, ownership, encryption identity and environment-specific credentials/capabilities. Inspect the pre-open gate that applies new mappings, revocations and publication policy before restored data becomes available. Compare a synthetic restore into its rightful tenant with a changed target principal/environment; a backup authorized for an infrastructure operator is not automatically authorized for an application tenant.

## Discriminating verification

Use isolated owned tenants and a synthetic backup; compare legitimate restore with an unauthorized source/target pairing.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An administrator-approved recovery is not tenant exposure; a backup identifier or restore job ID is not restored-data access.

## Repair acceptance

Bind backup source, requester and restored destination authority, verifying legitimate recovery and target isolation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
