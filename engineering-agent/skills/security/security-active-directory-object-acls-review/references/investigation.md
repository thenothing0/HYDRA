# Investigation: Active Directory effective object control and delegated identity changes

## Trace in the actual implementation

Resolve the effective principal right on the exact object and trace it into a protected attribute, membership or credential operation.

## Implementation decisions

Evaluate inherited ACE applicability, deny/allow semantics, group membership and protected-object behavior for the exact property/control right. GenericWrite and ownership/control rights can have different material effects. Read-only ACL exports can establish a delegation path, but a successful directory login or one permissive ACE alone does not prove arbitrary domain-wide control.

## Operational method

Resolve the object/property GUID, inherited-object type and inherit-only/applicability flags for each relevant ACE. Evaluate the actual token group set and effective descriptor, including protected-object inheritance behavior, before interpreting GenericWrite/ownership/control rights. Bind one permitted directory operation and one forbidden property/control right to that effective access decision. An isolated permissive ACE or membership display is not a complete domain-control path.

## Discriminating verification

Use owned lab objects and synthetic principals or configuration-only proof; compare legitimate delegated management and a prohibited object/attribute.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An ACE name without inheritance/group resolution is not effective control; read access or a denied write is not escalation.

## Repair acceptance

Constrain delegation and inheritance while preserving intended administration, then verify actual allowed/denied rights.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/windows/win32/ad/object-and-attribute-protection)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
