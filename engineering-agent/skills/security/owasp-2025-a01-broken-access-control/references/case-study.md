# Disclosed case — CVE-2023-22515

- Publisher: Atlassian
- Publication date: 2023-10-04
- Retrieved: 2026-10-26
- [Original report/advisory](https://confluence.atlassian.com/security/cve-2023-22515-broken-access-control-vulnerability-in-confluence-data-center-and-server-1295682276.html)
- OWASP A01:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Atlassian reported unauthorized administrator creation on affected Confluence Server and Data Center installations. Its cloud service was excluded; releases before 8.0.0 were excluded. Historical fixed lines included 8.3.3, 8.4.3, and 8.5.2. These are historical fixes, not current deployment recommendations.

## Operational lesson

Review setup and administrative lifecycle endpoints as well as normal object routes. An upgrade and an investigation of possible prior compromise are separate work items.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
