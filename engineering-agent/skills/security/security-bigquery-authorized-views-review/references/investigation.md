# Investigation: BigQuery authorized view/routine data projection and delegation

## Trace in the actual implementation

Follow whether a caller can modify an authorized view/routine or use its projection to access data beyond the intended exposure contract.

## Implementation decisions

Determine whether a view, routine or authorized dataset grants deliberate access to a projection without source-table read rights. Track who can modify that trusted object and its SQL. A user querying the intended view is expected; the defect is excess rows/columns or untrusted modification that changes the delegated projection.

## Operational method

Record whether delegation targets one authorized view, one authorized routine or an authorized dataset that can include future views. Identify who may create/replace the delegated object and which dataset/table projection it can query. Compare a fixed permitted projection with a changed projection authored by the actual restricted editor. Metadata visibility is not source-table read access; authorized creation within a delegated dataset can be a separate authority path from editing a single view.

## Discriminating verification

Use owned synthetic datasets and compare intended view output with a controlled modification or restricted direct-table query.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Reading an intentionally public aggregate is expected; table metadata or a denied direct query does not prove excessive view authority.

## Repair acceptance

Constrain authorized-resource modification and projection, then verify intended queries and protected fields remain unavailable.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/bigquery/docs/authorized-views)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
