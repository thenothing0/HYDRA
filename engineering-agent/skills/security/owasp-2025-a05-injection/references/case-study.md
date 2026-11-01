# Disclosed case — CVE-2022-34265

- Publisher: Django
- Publication date: 2022-07-04
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.djangoproject.com/weblog/2022/jul/04/security-releases/)
- OWASP A05:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

Django disclosed SQL injection where untrusted input reached Trunc(kind) or Extract(lookup_name). Applications restricting these choices to a known safe list were excluded. Historical patched releases included 4.0.6 and 3.2.14.

## Operational lesson

ORM use does not make attacker-controlled SQL structure safe. Trace values and structural selectors separately; verify trusted mappings for identifiers and date-part choices.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
