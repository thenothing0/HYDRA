---
name: security-grpc-authorization-review
description: "Review gRPC service authorization across unary, streaming and gateway paths. Use for interceptor coverage, metadata identity and per-message resource authority."
---

# gRPC method, object and stream authorization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Inventory exposed service/method descriptors, gateway routes, credentials and server interceptor/handler chains. Trace metadata through trusted authentication to actor/tenant and per-method/resource checks in the actual language/runtime.

2. Use an owned local service and two synthetic identities to compare an allowed RPC with a forbidden method/object request. For streams, observe the authorization boundary for later resource-bearing messages as well as establishment, without assuming a single universal revalidation cadence.

3. Inspect methods excluded from shared middleware, trusted-proxy metadata, gateway/direct transport differences, token expiry/revocation policy and error handling. Distinguish transport TLS, authenticated principal and authority for the requested object/action.

4. Apply complete method/handler coverage and enforce the required object/stream lifecycle policy. Retest valid unary/stream traffic, denied actor/object, changed session state and gateway/direct equivalents where both are in scope.

## Evidence decisions

Enabled reflection, a discoverable method or a successful TLS handshake is not an authorization bypass. An UNAUTHENTICATED/PERMISSION_DENIED label alone does not prove that no protected effect occurred.

Provide service/method/version, interceptor and gateway coverage, verified actor metadata path, synthetic object/message sequence, resulting state/data and permitted-call control.

Inspect known authorized service surfaces; do not enumerate unrelated network services or stress long-lived streams.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **gRPC credentials/interceptors; TLS authentication is separate from application authorization**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://grpc.io/docs/guides/auth/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
