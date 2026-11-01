---
name: security-dom-clobbering-review
description: "Review HTML id/name collisions that alter browser globals or DOM properties. Use for DOM clobbering with a reachable navigation, script/configuration or authority consumer."
---

# DOM named-property collisions and security consumers

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) provides capability/fallback rules across agents; no sibling skill or vendor API is required.

## Investigation

1. Trace attacker-authorable non-script markup through sanitization to named-property lookups and the actual consumer. Record whether a DOM element/collection replaces the trusted value and how code coerces or reads that value.

2. Use an isolated browser page with harmless IDs/names and a local marker destination or inert stub sink. Compare ordinary allowed markup, observe the resolved value/type and demonstrate the changed protected consumer rather than only the named property.

3. Inspect form/document/window properties, duplicate named elements, load order and sanitization configuration for the deployed browser/library. Separate a collision primitive from XSS, navigation or other impact and respect required rich-content behavior.

4. Use explicit scoped trusted state and appropriate type/authority checks at the consumer, plus suitable markup handling. Retest allowed rich content, attempted collisions and the actual consumer on the relevant browser path.

## Decision and evidence

An element having an id/name or appearing as a global is not itself a security finding. A collision that never reaches a protected consumer does not demonstrate the claimed downstream impact.

Include markup placement authority, sanitizer/browser/build context, collision lookup and resulting type/value, consumer trace, inert observed effect and legitimate-markup control.

Use owned synthetic identities/records and bounded reversible verification. Stop on unexpected exposure, unrelated effects or degradation and continue statically where useful. State the decisive missing check rather than inventing observations. Source-supported confirmation and dynamic confirmation must be labeled accurately.

## Report and closure

Write one report per independent root cause with [finding-template.md](assets/finding-template.md). Include expected/observed behavior, prerequisites, minimal reproduction, demonstrated impact, contextual severity, evidence and limits. Keep related ingress paths into the same defect together; explain independent chain components instead of duplicating one issue.

[Report handoff](references/report-handoff.md) covers the owner/policy/channel and platform-template workflow, including manual operation if other skills are absent. Optional security-finding-report, security-disclosure-routing and security-platform-report can prepare the per-finding draft. They do not authorize external transmission. Optional security-retest-verification and security-triager-response support later evidence-based follow-up.

Retest the original failure, legitimate control and relevant state effects on the changed build before closing a fix. A patch without execution remains patched-unverified where runtime verification is required for the claim.

## Planning cases and references

[Control catalog](assets/control-catalog.json) is a planning aid. [Review cases](assets/review-cases.json) are authored scenarios, not completed tests. An initial OWASP A05:2025 planning lens is not a confirmed final classification; select taxonomy/CWE from the actual root cause or leave it unmapped.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html) — accessed 2026-10-27. WSTG links, where used, pin v4.2 scenarios; apply current implementation/provider documentation to version-sensitive behavior. Reference access is not an exhaustive public-report survey or a target assessment.
