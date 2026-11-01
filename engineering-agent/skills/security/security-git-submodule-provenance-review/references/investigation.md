# Investigation: Git submodule revision/source trust in a privileged build

## Trace in the actual implementation

Trace who can change the submodule URL/revision and whether the approved parent revision actually binds the bytes later built.

## Implementation decisions

Bind .gitmodules URL changes, the committed gitlink SHA, recursive submodules and any update --remote behavior. A pinned SHA narrows content identity but does not prove an approved producer or safe build scripts. Rewriting a local URL is privileged fixture setup unless the protected build actually consumes an attacker-editable configuration source.

## Discriminating verification

Use inert owned repositories and a local checkout; compare pinned intended content with an untrusted URL/ref update without running builds.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

The presence of submodules is not a supply-chain flaw; approved immutable submodule content can be valid.

## Repair acceptance

Bind submodule source and revision to reviewed provenance, retesting recursive updates and approved release behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://git-scm.com/docs/git-submodule)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
