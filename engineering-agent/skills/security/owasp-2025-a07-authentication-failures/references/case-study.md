# Disclosed case — CVE-2023-7028

- Publisher: GitLab
- Publication date: 2024-01-11
- Retrieved: 2026-10-26
- [Original report/advisory](https://docs.gitlab.com/releases/patches/patch-release-gitlab-16-7-2-released/)
- OWASP A07:2025 mapping: analyst assessment of the failure mode; not a claim that the publisher assigned this edition’s category.

## What the source establishes

GitLab disclosed password-reset delivery to unverified email addresses in affected 16.x branches and published fixes/backports. The advisory distinguishes password reset from full account takeover when 2FA remains required. Historical release notes also mention later migration-related patches.

## Operational lesson

Verify recovery recipient ownership independently of account lookup. Demonstrate reset, login, and MFA consequences separately; use supported current releases rather than blindly adopting historical first-fix versions.

## Applicability and limits

Match the affected product, version/build, configuration, and reachable feature to primary evidence. Consult the full original advisory for complete affected branches, exclusions, updates, and response actions. Check the currently supported release before proposing an upgrade. Do not infer compromise solely from a version match. The local lab is an original small fixture for the relevant property, not a reproduction of this CVE or proof of coverage for the real product.
