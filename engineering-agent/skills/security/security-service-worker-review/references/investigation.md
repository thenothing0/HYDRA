# security-service-worker-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect worker registration scope, controlled clients, fetch routing, cache keys and account/logout/update policy. Distinguish worker CacheStorage from intermediary HTTP caches.

## Decisive experiment and source trace

Cache a private synthetic account-A response via the normal feature, then perform the declared logout/account-switch flow and request the same resource as B/offline. Observe the source and marker of the returned response. Separately trace untrusted control of worker script URL or registration scope only if the application exposes such a path.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A worker being registered or private data being available offline to its rightful account is not itself a leak. Browser storage partitioning, scope and lifecycle prerequisites must match the tested context.

## Repair acceptance

Bind private cache entries and lifecycle cleanup to the declared account policy; use trusted worker code/registration inputs. Retest intended offline behavior, logout/account switch and the evidenced update path.

## When the next edge is unavailable

Without the worker/cache implementation or an account lifecycle contract, request the missing artifact; do not infer cross-account reuse from a cache key string alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
