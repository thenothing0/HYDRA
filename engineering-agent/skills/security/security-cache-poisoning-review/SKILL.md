---
name: security-cache-poisoning-review
description: "Review cache-key, cacheability and response trust boundaries for poisoning/deception. Use for isolated cache tests and authorization-sensitive response reuse."
---

# Web cache poisoning and deception

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Identify the actual cache layer, key components, unkeyed inputs, variation, normalization and authenticated-response policy. Trace which input can alter a cacheable response.

2. Use a dedicated synthetic path/cache key with a harmless marker and a cleanup/expiry plan. Compare producer and controlled consumer views; avoid popular shared URLs or content that could harm unrelated users.

3. Separate reflected uncached input from stored cross-request influence. Inspect routing/path disagreement for deception and whether a victim-like controlled response actually becomes retrievable by another actor.

4. Repair key/variation, trust of response-generating inputs and cacheability rules. Retest cold/warm legitimate behavior, private response isolation and rejection/removal of the synthetic marker.

## Discrimination and evidence

A cache header, reflection or timing difference is not poisoning. A cache miss or a body intended to be public is a discriminator, not proof of safe private behavior.

Include cache identity/key model, marker lifecycle, controlled producer/consumer requests, hit evidence and actual protected-content or response-integrity consequence.


## Classification and reporting

The initial planning lens is OWASP A06:2025 and CWE-444; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://portswigger.net/web-security/web-cache-poisoning) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
