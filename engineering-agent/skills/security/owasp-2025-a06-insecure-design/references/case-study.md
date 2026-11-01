# Disclosed case — Stripe repeated discount redemption case

- Publisher: HackerOne
- Publication date: 2024-11-01
- Retrieved: 2026-10-26
- [Original report/advisory](https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption)
- OWASP A06:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

HackerOne described a disclosed Stripe discount-redemption flaw in which parallel acceptance requests applied a benefit repeatedly. Its account notes that an initial additional check still left a race condition. This is a platform case study, not a CVE or a claim that every coupon system has the flaw.

## Operational lesson

A sequential guard is insufficient when the invariant spans a concurrent read and write. Test the transaction or uniqueness boundary and count committed benefits.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
