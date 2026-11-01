---
name: security-xss-review
description: "Review browser script execution across reflected, stored and DOM data flows. Use for XSS; distinguish escaped reflection, self-only behavior and intended rich content."
---

# Cross-site scripting: reflected, stored and DOM

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace input and decoding through storage, templates, browser parsing and DOM sinks. Identify the actual HTML/attribute/URL/script context and which user can place and encounter the content.

2. Use a harmless DOM marker in an isolated account/page and compare a literal text control. Distinguish server reflection, client-only transformation and stored rendering after reload; do not read credentials or reach other users.

3. Review alternate consumers such as previews, administrative views, email/browser renderers and client hydration. Establish whether an actor can cross into another permitted test identity’s view before describing cross-user impact.

4. Repair the relevant sink with context-correct handling and a supported sanitizer for intentionally allowed HTML. Retest valid rich content, quotes/Unicode, inert hostile-looking input and the actual browser consumer.

## Evidence and discrimination

Reflection, a blocked payload, a scanner label or executable content only the same actor can already author is not enough to establish the claimed cross-user risk.

Capture placement actor, viewer role, input-to-sink context and controlled browser effect. Separate actual execution from unverified account takeover or data theft.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-79; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
