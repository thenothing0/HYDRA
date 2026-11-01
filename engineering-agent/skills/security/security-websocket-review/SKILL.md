---
name: security-websocket-review
description: "Review WebSocket handshake, origin/session binding, message authorization and lifecycle. Use for cross-site socket access and per-message object trust boundaries."
---

# WebSocket session and message authorization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map handshake authentication/origin, upgraded connection context, message types, subscriptions, object lookups and session expiry/logout behavior.

2. Use two controlled accounts and synthetic objects to compare permitted/denied subscriptions and messages. For cross-site effects use an owned browser origin and record whether ambient credentials and origin policy permit access.

3. Inspect message-level authorization after connection, role/session changes, reconnect paths and bounded schema/size handling. Do not flood the service or subscribe to unrelated private streams.

4. Enforce the intended origin/session and per-message policies, then retest allowed traffic, denied object actions, lifecycle invalidation and no leaked queued messages.

## Discrimination and evidence

A successful protocol upgrade is not proof of authorization bypass. Origin policy alone does not replace authentication and message permissions; an authenticated connection may still lack object authority.

Include handshake context, redacted labeled messages, object/actor matrix, session lifecycle and actual messages/state delivered across the prohibited boundary.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-862; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
