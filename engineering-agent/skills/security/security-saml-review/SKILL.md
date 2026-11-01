---
name: security-saml-review
description: "Review SAML XML signature, assertion selection and service-provider binding. Use for SAML trust/identity confusion rather than generic XML parser review."
---

# SAML assertion and federation binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map IdP/SP metadata trust, signature verification and the exact assertion/subject consumed. Trace audience/recipient, request/response correlation, time conditions and local account mapping.

2. Use dedicated synthetic IdP/SP fixtures and controlled identities to vary one binding or assertion property. Confirm rejection on the actual authenticated path without sharing real assertions or keys.

3. Inspect multiple/nested assertion handling, canonicalization/library APIs, replay storage and alternative login flows. A verified element must be the one whose claims grant authority.

4. Use supported federation components and explicit trust/binding policy. Retest valid assertions, wrong authority/recipient/correlation, expired/replayed fixtures and the resulting local identity.

## Evidence and discrimination

A signed XML document alone is not proof that the consumed assertion was validated. Library presence, a parser error or issuer text does not establish identity compromise.

Document metadata/key trust, verified-versus-consumed element, SP binding contract, synthetic claim/identity consequence and legitimate login control.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A07:2025 and CWE-347; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
