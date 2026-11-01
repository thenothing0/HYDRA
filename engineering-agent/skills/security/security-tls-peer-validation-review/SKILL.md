---
name: security-tls-peer-validation-review
description: "Review application TLS clients for trusted peer identity and certificate validation. Use for disabled verification, hostname/reference-identity mismatch and insecure fallback paths."
---

# TLS service-identity and certificate validation in clients

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace the actual client/library, reference service identity, trust anchors and certificate-validation options to the authenticated connection. Distinguish transport encryption, trusted certificate chain and matching service identity; record deployment-specific private trust requirements.

2. Use a loopback test server with synthetic trusted and wrong-identity/untrusted certificates and the real client configuration. Confirm rejection before application secrets/data are sent and retain a valid private-CA control; do not intercept real traffic or install a machine-wide root.

3. Inspect redirects, proxies, custom verifier callbacks, retry/fallback connections and environment overrides that reach this client. Keep peer authentication separate from application token authorization and from an optional certificate-pinning policy.

4. Use supported certificate and reference-identity verification with narrowly provisioned trust and fail-closed fallback. Retest the intended server, wrong identity, untrusted chain and the relevant alternate connection path on the deployed runtime.

## Decision and evidence

A private CA, encrypted connection or absence of pinning alone is not a defect. A browser warning on an unrelated endpoint does not establish that the application client accepts an invalid peer.

Include client/runtime/build and verification settings, reference identity/trust model, synthetic certificate properties, handshake and pre-data-send result, fallback trace and valid-peer control; exclude private key material.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A04:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://www.rfc-editor.org/rfc/rfc9525) — accessed 2026-10-27. Use the primary reference for the relevant protocol/provider and check implementation-specific behavior for the deployed version. A contextual source does not itself establish a product requirement. Reference access is not an exhaustive public-report survey or a target assessment.
