# Disclosed case — CVE-2008-0166 / DSA-1571-1

- Publisher: Debian
- Publication date: 2008-05-13
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.debian.org/security/2008/dsa-1571)
- OWASP A04:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Debian disclosed a distribution-specific OpenSSL change that made key generation predictable. The advisory called for upgrading and recreating affected key material; imported weak keys could affect other systems. GnuPG and GnuTLS generated keys were excluded.

## Operational lesson

Repairing a random generator does not repair secrets previously generated with it. Track provenance of key material and plan replacement, revocation, and migration.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
