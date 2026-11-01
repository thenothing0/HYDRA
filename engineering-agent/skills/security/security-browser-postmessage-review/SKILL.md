---
name: security-browser-postmessage-review
description: "Review cross-window postMessage and MessagePort trust in web applications. Use for untrusted peers invoking sensitive actions or receiving protected responses."
---

# Browser postMessage peer and capability trust

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map message senders/listeners, window relationships, exact origin checks, expected peer/source and message schema to sensitive consumers. Distinguish ordinary public notifications from privileged requests and transferred channel capabilities.

2. Use two controlled browser origins and owned sessions to send a harmless request from the wrong peer, with an expected-peer control. Capture browser-created event origin/source and observed synthetic effect; a manually dispatched same-page event is not a remote-origin proof.

3. Inspect window navigation between handshake and reply, wildcard destinations for sensitive data, opaque/null origins and transferred ports. Once a port carries authority, review how that capability is distributed and revoked rather than assuming origin checks on every port message.

4. Bind sensitive communication to the appropriate origin/peer/session and validate message structure and action authority. Retest legitimate embeds, wrong origin/peer, navigated windows and rejected privileged requests using the browser behavior relevant to the application.

## Evidence decisions

A wildcard destination carrying public data or a missing origin check on a harmless listener is not automatically exploitable. Prove access to the window/channel and the specific protected effect.

Include window/channel setup, origins and peers, browser/version, listener/action trace, synthetic request/response, actual sensitive boundary and intended-integration control.

Use owned test windows and canaries; do not deliver messages into unrelated users' sessions or collect their data.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **HTML cross-document/channel messaging; validate origin, peer and message contract**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://html.spec.whatwg.org/multipage/web-messaging.html) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
