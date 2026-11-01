---
name: security-postgres-rls-review
description: "Review PostgreSQL row-level security using the real application role and tenant context. Use for USING/WITH CHECK coverage, bypass roles and connection-pool context leakage."
---

# PostgreSQL row-security policy and runtime-role isolation

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Record PostgreSQL version, runtime role/membership, table ownership, RLS/FORCE state and policies per command. Trace tenant/user context from trusted authentication through pooled transactions to policy expressions; table permissions and row policy are separate controls.

2. Use a disposable database with two synthetic tenants and the actual nonprivileged application role. Compare permitted and forbidden SELECT/INSERT/UPDATE/DELETE operations as applicable, recording row results and persisted effects. An owner/superuser session is not a substitute for the runtime role.

3. Review policy combination, USING versus WITH CHECK, role bypass, security-definer/view paths and whether caller-accessible SQL can alter trusted context. Test connection reuse and rollback/context reset against the actual pool mode without assuming RLS covers whole-table operations.

4. Correct the policy, role authority and trusted context lifecycle for the supported access paths. Retest required cross-tenant administration separately, denied tenant reads/writes and consecutive requests on reused connections with correct cleanup.

## Decision and evidence

Table owners, superusers or BYPASSRLS roles can behave differently by design. Their row visibility alone is not a tenant bypass unless the application actually runs with that authority or delegates it to the claimed actor.

Include role/table/policy snapshots and version, trusted context source, transaction/pool mode, synthetic row ownership, query outcomes and write effects, bypass prerequisites and legitimate tenant/admin controls.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A01:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
