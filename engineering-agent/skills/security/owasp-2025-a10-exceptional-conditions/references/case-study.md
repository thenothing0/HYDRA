# Disclosed case — CVE-2020-29652

- Publisher: Go team
- Publication date: 2020-12-16
- Retrieved: 2026-10-26
- [Original report/advisory](https://groups.google.com/g/golang-announce/c/ouZIlBimOsE)
- OWASP A10:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

The Go team disclosed that a crafted authentication method could panic SSH servers when an optional GSSAPI configuration was nil. The announcement identifies the fixed golang.org/x/crypto pseudo-version as v0.0.0-20201216223049-8b5274cf687f.

## Operational lesson

A disabled optional capability still needs a guarded dispatch path. Check absent configuration and malformed dependency results before dereference, with a legitimate capability-enabled control.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
