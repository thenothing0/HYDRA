---
name: security-mobile-local-data-review
description: "Review Android/iOS sensitive data in files, databases, backups and platform caches. Use for storage access and retention boundaries with an explicit device threat model."
---

# Mobile local data, backup and retention exposure

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Define the sensitive field, retention policy and attacker capability: another app, backup recipient, shared device or privileged device access. Trace writes to storage, platform caches and backup/export paths in the release configuration.

2. Seed an owned device with a synthetic marker and inspect only the agreed storage/backup surface. Record which identity and device state can recover it, comparing a deliberately public field. Emulator shell access is evidence of a prerequisite, not a universal attacker capability.

3. Follow sign-out, account switch, restore and deletion through caches, database journals and shared containers where applicable. Inspect platform key/storage protections and whether the same actor can obtain both protected data and its key.

4. Apply the platform-appropriate protection, minimize copies and enforce required retention/backup rules. Retest normal offline use, approved restore, denied access and account-lifecycle cleanup against the stated threat model.

## Evidence decisions

A plaintext value visible only to the already-authorized app or a rooted/debug device does not by itself establish the claimed exposure. Encryption is not a substitute for access and key policy.

Provide data classification, device/OS/build state, precise location and lifecycle, actor access prerequisites, redacted synthetic marker recovery, retention requirement and unaffected legitimate use.

Do not label lack of certificate pinning or root detection as this storage defect; route separate issues only when their own security boundary is evidenced.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **MASVS-STORAGE-1 and MASVS-STORAGE-2 as applicable**. The catalog's OWASP A04:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
