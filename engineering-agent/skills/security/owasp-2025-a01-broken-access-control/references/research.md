# Research and verification — A01:2025

Reviewed 2026-10-26. This is a curated source set, not an exhaustive incident-report corpus. The workflow and acceptance fixture are original guidance; the official category page supplies the taxonomy. No real target was tested.

## Primary sources

- [Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) — retrieved 2026-10-26; HTTP 200. Use for category boundary, mapped CWEs, official prevention notes, and illustrative attack scenarios.
- [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.

## Applying external reports

When a report or advisory is supplied, preserve its URL, publisher, publication/update date, affected versions, prerequisites, claimed result, and fixed version. Verify the original publisher and compare the affected configuration with the target. Label a category assignment as an analyst mapping unless the source makes it explicitly. Never transfer a report's severity to a different deployment without evidence. Distinguish an official illustrative scenario from a disclosed incident.

## Verification fixture

A tenant-B fixture must remain unreadable and unchanged when requested with tenant-A credentials, while its owner retains access. A destination outside the documented fetch policy must be denied before any network attempt.

Capture the setup, relevant code/configuration, expected outcome, observed outcome, and side-effect check. Include both the failing case and a permitted control. If only static evidence is available, report the source-to-decision trace and mark dynamic verification pending.

## Standards mapping

Use [ASVS](https://asvs.owasp.org/) for explicit security requirements and the [WSTG project](https://owasp.org/www-project-web-security-testing-guide/) for applicable testing methods. Pin any requirement or test identifier to the edition actually consulted; do not fabricate identifier mappings. The Top 10 is an awareness taxonomy, not a full verification checklist.
