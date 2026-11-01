# Investigation: OpenSearch snapshot repository registration and restore authority

## Trace in the actual implementation

Follow who may create/change repository destinations or restore data into indexes with different confidentiality/authorization semantics.

## Implementation decisions

Separate repository registration, snapshot creation, restore and security-index restrictions. Restoring an owned snapshot into an allowed test index may be intended. Inspect whether the caller can select another tenant data or privileged index, and whether repository credentials belong to the node service; do not execute production restores or list unknown backup contents.

## Operational method

Collect security-plugin/version settings, permitted restore APIs, selected indices and whether global/security state can be included. Separate repository registration/storage credentials used by the node from the caller allowed to restore into an index. Inspect the actual registration and restore checks plus a supplied or isolated denied-index control; an object-store credential held by the node does not itself grant a tenant snapshot or cluster-state authority.

## Discriminating verification

Use an isolated owned cluster and synthetic snapshot repository; compare permitted backup/restore and an out-of-policy repository/index selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Snapshot listing is not data extraction, and an administrator-authorized restore is not a tenant bypass.

## Repair acceptance

Constrain repository/restore authority and storage credentials, verifying legitimate recovery and tenant separation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.opensearch.org/latest/tuning-your-cluster/availability-and-recovery/snapshots/index/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
