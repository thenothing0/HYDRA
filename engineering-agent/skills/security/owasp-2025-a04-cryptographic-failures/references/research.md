# Research and verification — A04:2025

Reviewed 2026-10-26. This is a curated source set, not an exhaustive incident-report corpus. The workflow and acceptance fixture are original guidance; the official category page supplies the taxonomy. No real target was tested.

## Primary sources

- [Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/) — retrieved 2026-10-26; HTTP 200. Use for category boundary, mapped CWEs, official prevention notes, and illustrative attack scenarios.
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.

## Applying external reports

When a report or advisory is supplied, preserve its URL, publisher, publication/update date, affected versions, prerequisites, claimed result, and fixed version. Verify the original publisher and compare the affected configuration with the target. Label a category assignment as an analyst mapping unless the source makes it explicitly. Never transfer a report's severity to a different deployment without evidence. Distinguish an official illustrative scenario from a disclosed incident.

## Verification fixture

Modified ciphertext must fail closed before consumers receive plaintext. A controlled old record remains readable during the approved migration window, while newly written records use the new format/key identifier.

Capture the setup, relevant code/configuration, expected outcome, observed outcome, and side-effect check. Include both the failing case and a permitted control. If only static evidence is available, report the source-to-decision trace and mark dynamic verification pending.

## Standards mapping

Use [ASVS](https://asvs.owasp.org/) for explicit security requirements and the [WSTG project](https://owasp.org/www-project-web-security-testing-guide/) for applicable testing methods. Pin any requirement or test identifier to the edition actually consulted; do not fabricate identifier mappings. The Top 10 is an awareness taxonomy, not a full verification checklist.
