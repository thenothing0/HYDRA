# Research and verification — A03:2025

Reviewed 2026-10-26. This is a curated source set, not an exhaustive incident-report corpus. The workflow and acceptance fixture are original guidance; the official category page supplies the taxonomy. No real target was tested.

## Primary sources

- [Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) — retrieved 2026-10-26; HTTP 200. Use for category boundary, mapped CWEs, official prevention notes, and illustrative attack scenarios.
- [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.
- [CI CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) — retrieved 2026-10-26; HTTP 200. Consult for implementation details relevant to the actual stack; verify current recommendations before patching.

## Applying external reports

When a report or advisory is supplied, preserve its URL, publisher, publication/update date, affected versions, prerequisites, claimed result, and fixed version. Verify the original publisher and compare the affected configuration with the target. Label a category assignment as an analyst mapping unless the source makes it explicitly. Never transfer a report's severity to a different deployment without evidence. Distinguish an official illustrative scenario from a disclosed incident.

## Verification fixture

An isolated build must resolve the intended dependency graph reproducibly, and the affected feature test must pass on the fixed version. Confirm that the shipping image or bundle no longer contains the affected version.

Capture the setup, relevant code/configuration, expected outcome, observed outcome, and side-effect check. Include both the failing case and a permitted control. If only static evidence is available, report the source-to-decision trace and mark dynamic verification pending.

## Standards mapping

Use [ASVS](https://asvs.owasp.org/) for explicit security requirements and the [WSTG project](https://owasp.org/www-project-web-security-testing-guide/) for applicable testing methods. Pin any requirement or test identifier to the edition actually consulted; do not fabricate identifier mappings. The Top 10 is an awareness taxonomy, not a full verification checklist.
