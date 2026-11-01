# Investigation: Warehouse query/export identity and destination publication authority

## Trace in the actual implementation

Follow the requester approved dataset/projection into an asynchronous export and the final readable destination, including user-selected storage paths.

## Implementation decisions

Separate query permission, export/job identity and destination reader rights. A service account can legitimately write an export where its caller cannot directly write, provided destination selection and result entitlement are constrained. Verify one owned synthetic result and exact destination ACL; a completed query job does not establish public delivery.

## Operational method

Select one actual warehouse export engine and retain query principal, row/column policy evaluation, job/service identity, export destination and final reader ACL. Trace whether projection and tenant filters apply before the service writes the artifact, and whether caller-controlled destinations widen its audience. A generic storage-writing worker stub cannot establish a warehouse-specific policy bypass. Compare an owned restricted projection with a permitted export and inspect delivered bytes, not just job success.

## Discriminating verification

Use owned synthetic tables and export destinations; compare rightful export with a restricted field, tenant or destination selection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Permission to run a public aggregate is not permission to export private rows; job acceptance alone does not show leaked bytes.

## Repair acceptance

Constrain data projection and destination authority, preserving intended export and denied unauthorized publication.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
