# Investigation: Gatekeeper/Kyverno policy exception and mutation trust

## Trace in the actual implementation

Trace who may change exceptions, selectors or authority-bearing labels and whether mutation creates a post-validation privilege difference.

## Implementation decisions

Identify the engine/version and whether a namespace, label or exception object exempts a resource. Check who can create that exception and whether admission protects the exemption metadata. Mutation and validation ordering can change the final admitted object; a policy report in audit mode is not an enforced deny control.

## Operational method

Choose the actual engine before constructing the exception case. For Kyverno inspect PolicyException availability, exception namespace/admission rules and which policies/rules it matches. For Gatekeeper inspect the applicable exclusion configuration and excluded namespaces/processes, rather than inventing a Kyverno-style object. Record the restricted actor allowed to alter the exemption and the final admission decision for one otherwise forbidden owned object; audit-only reports are not enforced denial.

## Discriminating verification

Use an owned local cluster with a harmless policy marker; compare an approved exception and a lower-trust exception/label change.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An explicit administrator-controlled exception is intended authority; policy names alone do not prove enforcement.

## Repair acceptance

Constrain exception writers and evaluate the final admitted object, preserving intended workload exceptions.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://kyverno.io/docs/exceptions/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
