# Research and verification — A07:2025

Reviewed 2026-10-26. This is a curated source set, not an exhaustive incident-report corpus. The workflow and acceptance fixture are original guidance; the official category page supplies the taxonomy. No real target was tested.

## Primary sources

- [Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) — retrieved 2026-10-26; HTTP 200. Use for category boundary, mapped CWEs, official prevention notes, and illustrative attack scenarios.
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.

## Applying external reports

When a report or advisory is supplied, preserve its URL, publisher, publication/update date, affected versions, prerequisites, claimed result, and fixed version. Verify the original publisher and compare the affected configuration with the target. Label a category assignment as an analyst mapping unless the source makes it explicitly. Never transfer a report's severity to a different deployment without evidence. Distinguish an official illustrative scenario from a disclosed incident.

## Verification fixture

A reset token for account A must not change account B and must fail on reuse. A token for the wrong issuer, audience, or purpose must be rejected by the actual protected application path.

Capture the setup, relevant code/configuration, expected outcome, observed outcome, and side-effect check. Include both the failing case and a permitted control. If only static evidence is available, report the source-to-decision trace and mark dynamic verification pending.

## Standards mapping

Use [ASVS](https://asvs.owasp.org/) for explicit security requirements and the [WSTG project](https://owasp.org/www-project-web-security-testing-guide/) for applicable testing methods. Pin any requirement or test identifier to the edition actually consulted; do not fabricate identifier mappings. The Top 10 is an awareness taxonomy, not a full verification checklist.
