# Investigation: Helm values and post-render transformations crossing deployment authority

## Trace in the actual implementation

Follow lower-trust values into security-sensitive rendered fields or post-render execution. Distinguish intended operator configuration from an untrusted tenant parameter.

## Implementation decisions

Rendered manifests are the security-relevant output, including dependencies, tpl evaluation and post-render changes. Values may intentionally grant chart configuration authority but must not silently exceed a caller contract. Render in an isolated non-cluster environment first; template evaluation and any external renderer are executable build inputs, not passive YAML parsing.

## Discriminating verification

Render an owned inert chart with permitted values and one untrusted security-field change; inspect the final manifest and release policy without installing it.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A chart supporting privileged options is not a vulnerability when only a trusted cluster operator controls them.

## Repair acceptance

Constrain exposed values and final admission policy, verifying legitimate rendering and blocked privilege changes.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://helm.sh/docs/chart_template_guide/values_files/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
