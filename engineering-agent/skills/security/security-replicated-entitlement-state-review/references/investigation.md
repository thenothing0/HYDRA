# Investigation: Authorization under multi-region or replica entitlement lag

## Trace in the actual implementation

Trace stale membership/session state into a protected decision after an authoritative change. Separate accepted bounded lag from undocumented continued access.

## Implementation decisions

Use the documented revocation completion time and actual routing/replica identity. A stale UI claim is not server authorization. An explicitly permitted grace interval is an expected state; an observed protected effect beyond it may identify missing propagation rather than a universal authentication bypass.

## Operational method

Retain decision provenance: replica/cache identity, entitlement generation read, routing/failover choice and protected consumer timestamp. A stale value shown in a log is not necessarily the value used for authorization. Under the declared propagation contract, compare the same revoked synthetic identity on fresh and stale paths and identify whether cache invalidation, decision-time recheck or replica routing is the missing enforcement edge.

## Discriminating verification

Use a deterministic owned two-replica fixture with delayed entitlement propagation and one synthetic protected operation before/after the allowed window.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Any replication delay is not automatically a vulnerability; identify the policy and observed protected effect beyond it.

## Repair acceptance

Use policy-appropriate consistency/invalidation and verify revocation, failover and entitled regional traffic.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
