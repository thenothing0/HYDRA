# Investigation: ECR image publication, tag mutation and deployment consumption

## Trace in the actual implementation

Trace a lower-trust image producer into the exact digest used by a privileged workload; distinguish readable images from writable release identity.

## Implementation decisions

Resolve the digest ultimately pulled by the workload; a mutable tag alone does not prove a protected deployment consumes attacker bytes. Separate repository push/delete policy, replication and deployment promotion authority. Signature/provenance verification must bind the consumed digest and authorized producer, and a legitimate release job remains a positive control.

## Operational method

GetAuthorizationToken authenticates a registry client but does not independently grant repository pull/push. Resolve permissions for actual layer upload, PutImage, retrieval and deletion on the selected repository. Record tag mutability, the pushed digest and the exact digest selected by deployment. An owned repository push is a baseline; the disputed path must change a protected repository or consumed release digest under the restricted principal.

## Discriminating verification

Use an owned local registry/sandbox repository and inert image metadata; compare approved digest selection with a forbidden tag replacement.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Public image pull is not deployment compromise. A mutable tag is insufficient without a reachable untrusted write and trusting consumer.

## Repair acceptance

Constrain publication and bind deployment to approved provenance/digest, preserving legitimate release updates.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
