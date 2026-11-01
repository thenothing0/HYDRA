---
name: security-ci-artifact-provenance-review
description: "Review build artifacts promoted into privileged release/deploy jobs. Use for producer/run identity, immutable digest binding and provenance verification at consumption."
---

# CI artifact promotion and producer identity

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Follow artifact production, naming, lookup, download, verification and execution/deployment. Identify the allowed repository/workflow/ref/run, exact digest and who controls each selector, including follow-up workflow events.

2. Use two harmless local artifacts with different producer metadata/digests and the real consumer selection logic or a faithful stub. Observe whether an untrusted producer can substitute content before any privileged use; avoid publishing a real package or deployment.

3. Inspect whether provenance is verified rather than merely generated, whether verification binds the expected producer and exact consumed bytes, and whether fallback paths bypass the gate. A hash alongside attacker-controlled bytes is not independent trust.

4. Bind promotion to the intended immutable artifact and authorized producer with fail-closed verification. Retest permitted promotion, wrong producer/digest/ref, absent verification material and the recovery path under the documented release contract.

## Evidence decisions

A valid signature or attestation alone does not authorize the producer for this deployment. Missing one particular attestation feature is not a defect when equivalent trust enforcement is evidenced.

Provide producer/consumer workflow revisions, artifact identifier/digest, attacker-controlled selector, verification policy and timing, substituted inert content result and valid-release control.

Use the chosen provider's current attestation/identity model; do not label a metadata-only fixture as a cryptographically verified attestation test.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **Artifact provenance verification; provider identity and consumer policy are distinct**. The catalog's OWASP A03:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
