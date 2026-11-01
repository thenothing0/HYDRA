# security-package-resolution-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read manifest/lockfile, index/source priorities, scopes, registry configuration and installer version. Inspect resolution without executing install hooks or publishing package names.

## Decisive experiment and source trace

Use local registry metadata/fixture names or a supported resolution-only path to determine which source/version wins for one private dependency. Compare the intended private source and an untrusted candidate under the exact configured resolver; do not assume all managers rank sources identically.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

An unregistered public name is not proof of dependency confusion. A lockfile, source binding, private index policy or scoped package ownership may prevent the hypothesized resolution.

## Repair acceptance

Bind packages to approved sources/ownership and preserve reproducibility/integrity. Retest intended updates and the exact ambiguous-source resolution without executing untrusted packages.

## When the next edge is unavailable

Without installer/version/configuration, record the candidate name and request that resolution context rather than claim arbitrary build code execution.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
