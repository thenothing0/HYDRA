# Disclosed case — CVE-2025-59476 / SECURITY-3424

- Publisher: Jenkins
- Publication date: 2025-09-17
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.jenkins.io/security/advisory/2025-09-17/)
- OWASP A09:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Jenkins disclosed forged console log lines via line breaks in attacker-controlled message content. Releases 2.528 and LTS 2.516.3 added inserted-line indicators. The advisory also cautions that other characters may mislead viewers.

## Operational lesson

Test the entire serialization-to-viewer path. A newline fix does not necessarily address backspace, directional characters, or an incorrectly parsed structured message.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
