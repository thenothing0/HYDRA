---
name: security-rag-authorization-review
description: "Review authorization in RAG ingestion, vector retrieval, reranking, citations and caches. Use for cross-user/tenant document exposure or stale entitlement propagation."
---

# RAG retrieval authorization and tenant isolation

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Trace document ownership and current entitlements through ingestion, chunk metadata, indexes, query filters, reranking, context assembly and citation access. Identify where the authenticated actor/tenant is bound and whether caller-supplied filters replace it.

2. Create two owned synthetic tenants with unique nonsecret canaries. Compare rightful retrieval with cross-tenant and revoked-access cases, capturing actual returned chunks/context and citation downloads separately from generated prose.

3. Inspect shared caches, conversation memory, index refresh, deleted documents and alternate search/export endpoints. Determine whether inaccessible content reaches the model/context even if the final answer happens to omit it.

4. Enforce current entitlement at every relevant retrieval/delivery boundary with trusted tenant binding and appropriate invalidation. Retest allowed retrieval, denied tenant/role, revoked membership and stale/cache paths using the same synthetic corpus.

## Evidence decisions

A plausible answer or guessed document title is not proof of private document retrieval. Establish the exact synthetic content/source and entitlement; deliberately shared corpus data may be intended.

Record tenant/actor/document policy, ingestion and filter trace, unique canary source, returned chunks/context/citation paths, entitlement-change timing and allowed-access control.

Use synthetic documents and explicit data-handling permission for external model calls; do not upload actual confidential documents merely to test isolation.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **OWASP LLM08:2025 and LLM02:2025 when supported by the data boundary**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
