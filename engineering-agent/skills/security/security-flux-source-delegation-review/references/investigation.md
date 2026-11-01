# Investigation: Flux source reconciliation and impersonated deployment identity

## Trace in the actual implementation

Trace who can reference or alter a source and which identity applies its rendered resources. Distinguish controller identity from per-reconciliation impersonation.

## Implementation decisions

Trace source artifact revision/digest into the Kustomization or HelmRelease and its effective serviceAccountName/controller identity. Source read access does not equal deployment edit authority. A namespace boundary can be crossed through allowed references only if the actual controller configuration and impersonated identity permit it; inspect cross-namespace-reference policy explicitly.

## Discriminating verification

Use an isolated fixture with two owned namespaces and inert manifests; compare intended source/account with a forbidden cross-namespace reference.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A source download alone is not privileged application; record the actual apply authority and admitted objects.

## Repair acceptance

Bind source references and reconciliation identities to tenants, preserving valid dependency and rollout behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://fluxcd.io/flux/security/best-practices/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
