# Investigation: NuGet package source mapping and transitive restore trust

## Trace in the actual implementation

Determine which source can satisfy each direct/transitive package ID and whether fallback or merged config defeats the intended mapping.

## Implementation decisions

Determine whether package source mapping covers direct and transitive IDs, and which existing cache/lockfile affects the restore. A cache hit may conceal the source that a clean restore would select. An intentionally mirrored trusted source is not dependency confusion; show an unintended producer selected for the protected package identity without publishing a package.

## Operational method

Resolve merged nuget.config files including clear elements and source names. For a package ID, exact mapping is more specific than prefix, a longer prefix is more specific than a shorter one, and wildcard is least specific; equal applicable mappings may still allow multiple sources. Keep global-packages cache hits separate from fresh source resolution. Compare one internal ID and a similarly prefixed external ID using a disposable cache and supplied or isolated restore metadata, not untrusted package execution.

## Discriminating verification

Use inert local feeds and package coordinates; compare intended source mapping with a controlled duplicate/fallback without executing package hooks.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Two configured feeds do not prove confusion; an unused package name or failed restore is not a selected untrusted artifact.

## Repair acceptance

Bind package families to intended sources and verify direct/transitive restore plus locked updates.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
- [Additional implementation reference](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
