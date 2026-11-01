# Investigation: Workload Identity Federation provider claims and service-account delegation

## Trace in the actual implementation

Trace external issuer claims into effective principals and distinguish provider admission from permission to impersonate a service account.

## Implementation decisions

Evaluate issuer, audience, attribute mapping and provider conditions before IAM principal/principalSet bindings. Attribute values such as repository name can be reassigned; immutable producer IDs may have different trust properties. Direct resource access and service-account impersonation are separate grants; a successful token exchange alone establishes neither final permission.

## Discriminating verification

Use an owned local claim-policy fixture or isolated test provider with two synthetic workloads; compare intended subject and a controlled claim mismatch.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Token exchange success alone does not establish target resource access; the impersonation/resource policy may still deny.

## Repair acceptance

Bind issuer attributes and delegation to the intended workload, then verify approved jobs and unrelated workload denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cloud.google.com/iam/docs/workload-identity-federation)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
