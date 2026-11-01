---
name: security-container-build-secrets-review
description: "Review container builds for secret persistence in layers, metadata, logs and cache exports. Use for Dockerfile/build-context and BuildKit secret lifecycle issues."
---

# Container build secret and layer retention boundary

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Trace a build credential from context, arguments, environment or supported secret mounts through build steps, intermediate stages, metadata and exported cache/image artifacts. Identify who can obtain each artifact rather than assuming only the final filesystem matters.

2. Build only a reviewed local fixture with a synthetic noncredential marker, no network and no privileged mounts. Inspect saved layers/metadata and intended output for that marker, comparing a valid public build input; do not build untrusted repository code for inspection.

3. Check commands that copy a mounted secret into output, log expanded values or export intermediate/cache content. A temporary mount protects delivery to the step, not every subsequent use by the command.

4. Use the supported secret delivery method and prevent persistence in distributable outputs. Retest the full image/cache/log recipients; owner-managed rotation is separate if a real credential was previously exposed.

## Evidence decisions

Deleting a secret in a later layer does not demonstrate removal from earlier artifacts. A secret mount declaration also does not establish that build commands avoid persisting its contents.

Provide reviewed build trace, artifact recipients, synthetic marker locations and hashes, final-versus-intermediate layer distinction, log/cache scope and required build behavior.

Focus on secret retention during builds. Generic dependency advisories and runtime container isolation belong to their own workflows.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **Docker BuildKit secret lifecycle and image/cache distribution**. The catalog's OWASP A03:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.docker.com/build/building/secrets/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
