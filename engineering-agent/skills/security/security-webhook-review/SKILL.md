---
name: security-webhook-review
description: "Review inbound webhook provider trust, exact-byte signatures, replay and idempotent effects. Use provider-specific protocol guidance rather than assuming one universal scheme."
---

# Webhook authenticity, replay and processing

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map provider/event identity, raw body handling, trusted secret/key selection, signature/time checks, event schema and the point of side-effect commitment. Confirm the actual provider contract.

2. Use a locally signed synthetic event to compare valid, changed-body and wrong-authority inputs. Observe rejection before state changes and avoid replaying real financial/customer events.

3. Review retries, delivery identity, event-type authorization, duplicate/out-of-order handling and key rollover. Authenticity alone does not prove safe business semantics or one-time processing.

4. Repair validation and atomic event processing for the provider/application model. Retest valid events, rejected tampering, duplicate delivery and approved recovery/rotation behavior.

## Evidence and discrimination

The presence of a signature header or HMAC utility is not end-to-end verification. Legitimate retries may be expected; the prohibited effect depends on the operation contract.

Provide provider-specific signature/body contract, local event/authority identity, verification-before-use trace, persisted effects and duplication policy; source guidance applies specifically to its provider.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A08:2025 and CWE-345; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
