---
name: security-android-components-review
description: "Review Android activities, services, receivers and providers exposed to other apps. Use for component caller permissions, intent-controlled operations and URI grants."
---

# Android exported components and caller authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Record the merged release manifest, OS/API and target SDK, component visibility, permissions and caller identity at each sensitive operation. Trace intent extras and content URIs to data or side effects; an intent filter is not an authorization rule.

2. Use an owned emulator and a separate low-privilege fixture app to exercise one harmless operation. Compare the intended caller with the fixture caller, recording actual returned synthetic data or state. A same-UID debug invocation cannot establish another app's authority.

3. Review delegated URI grants, pending operations, forwarded intents and internal component chains. Determine whether the original caller is preserved, revalidated or replaced by the app's own authority before a protected operation.

4. Reduce unintended exposure or enforce the appropriate caller permission and operation-level checks. Retest the legitimate inter-app flow, denied caller and delegated capability lifecycle on the release-equivalent build.

## Evidence decisions

An exported component can be an intended public entry point. Opening a screen is insufficient when the sensitive operation still enforces identity and permissions.

Include release manifest/build identity, OS/API, caller UID/permission model, component and operation, sanitized intent/URI input, expected caller policy and synthetic effect with a permitted control.

An emulator/root/debug-only observation must state its prerequisites; do not describe it as an unprivileged production-device exploit.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **MASVS-PLATFORM; refine the control from the observed boundary**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://developer.android.com/privacy-and-security/risks/android-exported) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
