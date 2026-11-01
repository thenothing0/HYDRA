# Investigation: WinRM/PowerShell remoting endpoint and constrained-command authority

## Trace in the actual implementation

Trace the authenticated caller into the exact endpoint and permitted commands/parameters, including helpers that delegate broader filesystem/process access.

## Implementation decisions

Resolve endpoint security descriptors, session configuration and JEA role capability files under the actual connecting principal. A constrained command can invoke a helper that holds broader authority; inspect helper inputs and executable provenance. A permitted remoting connection is not a full shell, and unrestricted administrator endpoints may be intentional.

## Operational method

Expand every role capability matching the connecting principal and compute the effective merged JEA capability set; permissions merge permissively, so another role can remove a parameter restriction present in one file. Include endpoint RunAs identity, visible providers/commands and wrapper implementation. Compare a constrained command under one role with the actual combined roles in an owned endpoint fixture; one .psrc alone does not establish confinement.

## Discriminating verification

Use an isolated owned endpoint and inert command stubs; compare intended constrained operation and one forbidden parameter/resource.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Remoting enabled or an available cmdlet name is not unrestricted execution; validate actual role capability and parameter binding.

## Repair acceptance

Constrain endpoint delegation and helper parameters, preserving intended remote administration.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)
- [Additional implementation reference](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities?view=powershell-7.6)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
