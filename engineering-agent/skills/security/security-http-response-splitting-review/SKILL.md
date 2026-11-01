---
name: security-http-response-splitting-review
description: "Review untrusted values entering response headers. Use for CRLF/header injection or response splitting, with actual serialized protocol behavior and isolated clients."
---

# HTTP response header structure and CRLF handling

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace external values and decoding into response header setters and the server/proxy serialization path. Identify the exact protocol/version and whether the application controls a value, a header name or raw response bytes.

2. Use a local server/proxy replica and a harmless X-Lab marker to compare ordinary text with a structural delimiter input. Capture actual serialized response parsing; a logged string or percent-encoded reflection is not a new header.

3. Inspect redirects, cookie/filename construction and transformations between protocol layers where applicable. Distinguish one injected header from an extra response/body boundary and from separately evidenced cache or browser impact.

4. Keep data within supported structured header APIs and reject invalid field structure at the serialization boundary. Retest valid header data, rejected delimiter input and consistent client/proxy parsing without shared cache effects.

## Decision and evidence

CRLF-like input in a log/body or a framework rejection does not prove header injection. A new harmless header alone does not establish full response splitting, session compromise or cache poisoning.

Record input-to-header path, decode/serialization layers, server/proxy/client versions and protocol, raw redacted local response, parsed marker field versus literal value and legitimate-header control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A05:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cwe.mitre.org/data/definitions/113.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
