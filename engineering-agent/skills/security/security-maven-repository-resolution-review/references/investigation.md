# Investigation: Maven repository/mirror resolution and executable build inputs

## Trace in the actual implementation

Trace actual repository precedence for dependencies and plugins, separating declared metadata from the effective source and verified artifact.

## Implementation decisions

Inspect effective settings, mirrors, repositories and plugin repositories rather than only pom.xml. Plugins and extensions execute during builds, while dependency resolution has its own selected coordinates/checksums. Do not run an untrusted Maven project to inspect it; use supplied effective models or an isolated resolver fixture without executing downloaded build code.

## Operational method

Derive one effective mirror per repository: exact mirrorOf repository-ID match takes precedence over wildcard matches, then evaluate exclusions and configured order. Resolve inherited repositories and pluginRepositories as separate executable-input paths; do not assume mirrors aggregate artifacts across all matches. Compare intended and disputed coordinates against supplied effective settings and resolver output, with caches identified. Inspect an untrusted build statically rather than executing its lifecycle to obtain an effective POM.

## Discriminating verification

Resolve inert local fixtures against owned repositories with conflicting harmless coordinates and record selected origin without executing plugins.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A repository URL or unused dependency declaration is not dependency confusion; prove the resolver selected the lower-trust artifact.

## Repair acceptance

Constrain mirrors/sources and artifact verification, testing intended updates and rejected origin substitution.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://maven.apache.org/guides/mini/guide-mirror-settings.html)
- [Additional implementation reference](https://maven.apache.org/guides/mini/guide-mirror-settings.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
