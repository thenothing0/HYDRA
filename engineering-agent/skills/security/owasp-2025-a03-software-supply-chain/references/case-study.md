# Disclosed case — CVE-2024-3094

- Publisher: Red Hat
- Publication date: 2024-03-29
- Retrieved: 2026-10-26
- [Original report/advisory](https://access.redhat.com/security/cve/cve-2024-3094)
- OWASP A03:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Red Hat describes malicious code in xz upstream release tarballs beginning with 5.6.0, with build inputs relevant to the compromise differing from the Git distribution. Its statement excludes RHEL and identifies affected Fedora development channels in its ecosystem.

## Operational lesson

A clean source checkout does not prove a release artifact is trustworthy. Match distribution, artifact origin, build path, and shipped binary; never classify all systems using xz as compromised.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
