---
name: security-secrets-exposure-review
description: "Review reachable credential/secret exposure and lifecycle risk. Use for leaked keys/tokens in code, artifacts, logs or client delivery without testing them against external services."
---

# Credentials and sensitive secret exposure

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Locate candidate values in the supplied source/artifact/log scope with redacted tooling output. Determine whether the value is a real security credential, a public identifier, test fixture or nonsecret configuration.

2. Trace the intended consumer, privileges, distribution/access path and any evidence of exposure. Establish reachability using minimal metadata; never copy full live values into reports or search engines.

3. Inspect lifetime, revocation history and whether build/history/log copies persist. Do not try the value against a service, enumerate its privileges or rotate it unless that additional action is explicitly in scope.

4. Recommend proportionate revocation/replacement and distribution cleanup through the owner’s workflow. Verify references and lifecycle remediation without treating repository deletion as proof of revocation.

## Evidence and discrimination

An API-looking string, public client key or known dummy fixture is not automatically a secret. A revoked credential may still have historical response implications, which need evidence.

Record redacted fingerprint/context, credential purpose, access path, supported privilege/lifetime information, unknown validity and owner-directed remediation requirements.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A07:2025 and CWE-798; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
