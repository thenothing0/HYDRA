# security-cache-poisoning-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map cache key, Vary behavior, cacheability, normalization, origin inputs and account partitioning at the actual cache. Distinguish poisoning from private-response reuse/deception.

## Decisive experiment and source trace

Use an isolated cache namespace or replica and a unique fixture path. Prime with the single suspect unkeyed input, then request as a separate clean controlled client without that input. Observe the poisoned marker, cache source and expected lifetime; purge owned fixture entries afterward.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Reflection visible only to the priming request is not poisoning. A cache miss or correct Vary separation defeats that test. Shared private data and attacker-altered public content have different impacts.

## Repair acceptance

Align response influence with cache keys or remove unsafe cacheability at the evidenced layer. Retest clean-client reuse, legitimate cache hits and private account separation where relevant.

## When the next edge is unavailable

Without an isolated namespace or cache provenance, continue source/config review; do not poison shared production paths to prove a cache hypothesis.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
