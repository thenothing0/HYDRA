# Investigation: sudo policy matching, delegated arguments and executable provenance

## Trace in the actual implementation

Resolve the exact matched command and who controls its executable, parameters, configuration and working-directory dependencies.

## Implementation decisions

Apply the installed sudo version matching rules to the exact executable and arguments before analyzing helper behavior. Wildcards, regular expressions, environment controls and writable executable/parent paths have distinct implications. A matcher granting a command is expected when policy intends it; the defect is an unauthorized semantic effect reachable through that permitted helper.

## Operational method

Retain installed sudo version, effective includes/order/tags, RunAs identity, canonical executable and how that version matches the command argument string. Resolve wildcard versus supported regex semantics rather than assuming shell argv matching. Inspect writable executable/parent paths, permitted environment and helper dependencies. A local argv recorder proves arguments only; validate the actual sudo matching decision from supplied policy/output or an isolated policy fixture before attributing the helper semantic effect.

## Discriminating verification

Use an isolated local policy fixture or inert argv-recording stub under owned identities; do not execute privileged escape payloads.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A sudo entry is intentional delegation; demonstrate unintended authority beyond its actual command and argument contract.

## Repair acceptance

Constrain the delegated operation and mutable inputs, verifying authorized commands and rejected argument/environment changes.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.sudo.ws/docs/man/sudoers.man/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
