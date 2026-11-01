---
name: security-ios-link-handling-review
description: "Review iOS universal-link and custom-URL handlers. Use for associated-domain routing, untrusted link parameters and sensitive action or account binding."
---

# iOS universal links, custom schemes and action binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map associated-domain configuration, association documents, custom schemes and app/scene handlers to the parsed route and operation. Record the installed build, actual domain association state and allowed action semantics.

2. On an owned simulator/device, open a harmless controlled link from outside the app and compare a valid intended link. Observe the account/resource/action selected after parsing, session checks and any required user confirmation.

3. Inspect percent decoding, nested URLs, fallback handlers, logged-out routing, cold/warm start and account-switch behavior. For callback identity confusion use the OAuth/OIDC workflow as appropriate rather than assuming a registered scheme proves takeover.

4. Validate the parsed route and parameters and enforce action/account authority independently of link delivery. Retest legitimate links, rejected destinations/actions and session changes across relevant handler paths.

## Evidence decisions

A custom scheme registration or universal link opening an app does not demonstrate a security issue. A link association determines routing; sensitive action authority needs separate evidence.

Record entitlement/association evidence, build/OS, external link source, handler path, normalization and selected account/action, observed synthetic result and valid-link control.

Assess only owned domains and test app identities; do not register an unrelated real application's scheme or claim a third-party domain.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **MASVS-PLATFORM; link association is separate from action authorization**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app.md) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
