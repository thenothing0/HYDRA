# Investigation: Cargo build scripts/proc macros and build-time authority

## Trace in the actual implementation

Trace lower-trust dependency/source selection into code executed during build, separating ordinary data dependencies from executable build hooks.

## Implementation decisions

Build scripts and procedural macros execute on the build host even when the final target is a different architecture. Review registry/git/path source selection and lockfile revision with the build sandbox. A crate declaring a build script is not itself malicious; demonstrate an untrusted source gaining capabilities outside the declared build trust policy.

## Discriminating verification

Inspect inert owned fixtures or run only a reviewed local stub that writes a harmless marker under bounded permissions.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A dependency capable of build-time code execution is not an exploit when it is intentionally trusted and correctly sourced.

## Repair acceptance

Constrain sources and build authority, verify provenance and preserve legitimate build-script functionality.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://doc.rust-lang.org/cargo/reference/build-scripts.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
