---
name: security-android-webview-review
description: "Review Android WebView JavaScript bridges, message channels and navigation trust. Use when web-controlled content can invoke native app capabilities."
---

# Android WebView content-to-native capability boundary

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map loaded top-level pages, frames, redirects, local content and all bridge/message registrations to native methods. Record which code controls each navigation and whether a method can identify or constrain its actual caller.

2. In an owned test build, route an untrusted fixture page to an inert native marker method and compare a trusted page. Observe the bridge invocation rather than assuming that JavaScript execution implies access to every app permission.

3. Inspect navigation transitions, frame reachability, bridge attachment/removal and URL parsing before load. Review file/content access only when it participates in this boundary, using the current WebView/Android implementation.

4. Keep privileged bridges away from untrusted content or use constrained origin-aware messaging and narrow native methods where supported. Retest redirects, embedded frames, blocked navigation and the intended trusted integration.

## Evidence decisions

JavaScript enabled in a WebView or use of a bridge alone is not a defect. Prove that lower-trust content reaches a protected native method under the claimed build and navigation state.

Capture WebView/build version, origin/frame/navigation chain, bridge registration, reachable method/authority, harmless native marker and the trusted-content control.

Use local fixture pages and stub native effects; no device data collection or calls to real financial/account operations are needed.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **MASVS-PLATFORM; distinguish web rendering from native capability exposure**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
