# Investigation: PHP stream-wrapper selection through lower-trust resource paths

## Trace in the actual implementation

Trace untrusted scheme/path input into the actual enabled wrapper and operation, distinguishing read, write, include and network effects.

## Implementation decisions

Identify the enabled wrapper and the exact consuming function; file reading, include/require, network fetching and archive metadata have different behavior. Version and configuration change historical assumptions. A wrapper-looking string rejected by the actual consumer proves no side effect; model with an inert local stream and do not trigger remote or deserialization gadgets.

## Operational method

Read the effective wrapper registry and the precise consumer function. Distinguish allow_url_fopen from allow_url_include and wrappers to which each applies; a local stream or include path is not equivalent to a remote fetch. For phar metadata inspect installed PHP behavior and any explicit metadata access rather than assuming all file operations deserialize it. Preserve the actual function/wrapper/configuration chain; a replacement inert wrapper demonstrates only its own semantics.

## Discriminating verification

Use an isolated local fixture with inert files and a reviewed wrapper stub; compare intended local resource and one prohibited scheme.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A wrapper name or allow_url setting is not arbitrary execution; the reachable consumer and effective operation determine impact.

## Repair acceptance

Constrain resource schemes and final path authority at the consuming call, preserving intended file operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.php.net/manual/en/wrappers.php)
- [Additional implementation reference](https://www.php.net/manual/en/phar.getmetadata.php)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
