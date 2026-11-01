---
name: security-graphql-review
description: "Review GraphQL resolver, field, node, batch and subscription trust boundaries. Use for GraphQL-specific security; classify each confirmed root cause separately."
---

# GraphQL authorization and execution controls

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map operations/resolvers and their registration, context identity, node lookups, field serializers, loaders and subscription lifecycle. Decide the root-cause category per finding rather than classifying every GraphQL issue as authorization.

2. With two controlled accounts and fixture objects, compare node/list/field and mutation access, including aliases/batching only when relevant. Verify denied writes through direct owner-side state.

3. Review query cost, pagination and batching limits statically or using bounded local instrumentation. Introspection alone is not automatically a vulnerability; do not perform live depth/resource exhaustion.

4. Enforce controls at resolvers/loaders/fields and resource admission boundaries. Test allowed fields and objects, mixed authorized batches, subscription changes and legitimate queries.

## Discrimination and evidence

A visible schema, error message or HTTP 200 response does not establish unauthorized data. Separate field leakage, object access, injection and resource-control findings by root cause.

Provide operation/variables, resolver path, actor/object permissions, selected fields, owner-side state and the relevant normal query control.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-862; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
