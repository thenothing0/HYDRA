---
name: security-password-reset-review
description: "Review recovery recipient/account/purpose binding and one-time reset lifecycle. Use for reset flows rather than a full authentication-system assessment."
---

# Account recovery and password-reset binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map request, verified recipient selection, token subject/purpose, expiry/storage, consumption, password update and any MFA/session consequences. Keep each stage distinct.

2. Use two controlled accounts and private inbox sinks. Verify that a token reaches only the intended recipient, cannot reset the other account and cannot be reused; use local clock fixtures for expiry.

3. Inspect alternative email/phone recovery, host-derived links, account-link changes, concurrent consumption and error paths. Avoid real-user enumeration, resets or mailbox interaction.

4. Repair the binding and atomic lifecycle through supported components. Retest valid recovery, wrong recipient/subject/purpose, expiration/replay and the declared old-session/MFA behavior.

## Evidence and discrimination

A generic success response does not prove delivery or takeover. Password reset is not full account takeover if an effective required factor still blocks login.

Provide controlled account/inbox roles, token lifecycle trace, stage-specific observed consequence, replay/expiry controls and the remaining MFA/session limits.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A07:2025 and CWE-640; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
