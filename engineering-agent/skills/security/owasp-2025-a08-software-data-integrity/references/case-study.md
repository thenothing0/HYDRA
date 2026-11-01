# Disclosed case — CVE-2017-1000353 / SECURITY-429

- Publisher: Jenkins
- Publication date: 2017-04-26
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.jenkins.io/security/advisory/2017-04-26/)
- OWASP A08:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Jenkins disclosed unauthenticated execution through serialized Java input to the remoting-based CLI, bypassing existing blocklist protection. Historical fixed releases were 2.57 and LTS 2.46.2; the advisory recommended disabling the remoting CLI in favor of other modes.

## Operational lesson

Inspect nested parsing and object construction, not just outer type checks. A deny list can miss an alternate object path; prefer constrained data and explicit allowed types without executing exploit gadget chains.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
