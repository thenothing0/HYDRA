# Disclosed case — JENKINS-47139

- Publisher: Jenkins
- Publication date: 2017-09-27
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.jenkins.io/security/advisory/2017-09-27/)
- OWASP A02:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

A first-start regression in Jenkins 2.80 left expected security defaults unset. Instances originally installed with that version needed security configuration review. Jenkins LTS was unaffected, and 2.81 repaired initialization for new weekly installations.

## Operational lesson

Test first boot, upgrade, and restore as separate configuration paths. Upgrading initialization code does not necessarily repair state already persisted insecurely.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
