---
name: security-aws-object-storage-review
description: "Review owned Amazon S3 bucket/object publication and access policy. Use for unintended read/write exposure, access points and signed-URL authorization boundaries."
---

# Amazon S3 object access and publication boundaries

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Identify the owned bucket/access point, intended audience and separate list, object read and object write policies. Review applicable policies, ownership/ACL mode and effective public-access controls; a bucket name is not an authorization finding.

2. Use one owner-provided synthetic object/key to compare the expected authorized actor with the agreed lower-trust actor. Confirm actual object bytes or a reversible isolated write only within scope, without enumerating unrelated objects.

3. Trace alternate distribution paths such as a CDN and presigned links. Record who can mint the capability, its scope/lifetime and whether the observed access is deliberately public; storage and CDN authorization may differ.

4. Repair the effective access boundary while preserving intentional public assets and approved signed access. Retest the same object/action/actor tuple, required delivery path and denied writes with cleanup evidence.

## Evidence decisions

Disabled block-public-access settings, bucket existence, public marketing assets or an owner-issued signed link alone do not establish private-data exposure or write access.

Include owner/scope evidence, synthetic key, intended audience/action, effective policy/config snapshots, access method and credentials state, redacted request/result and cleanup where relevant.

This workflow is S3-specific. For another provider, load its current authorization model instead of translating S3 controls by name.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **Amazon S3 bucket/object/access-point authorization and public-access controls**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
