---
name: security-aws-iam-review
description: "Review effective AWS IAM authorization for a specified principal, action and resource. Use for identity/resource policies, session context and excess privilege analysis."
---

# AWS IAM effective permission and authority review

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Define the intended principal/action/resource/context tuple. Collect the applicable identity and resource policies, role session, boundaries and organization controls available to the reviewer; record missing inputs instead of assuming their absence.

2. Evaluate that exact tuple using provider semantics and, when available, an authorized read-only analyzer/simulator. Record tool limitations and policy conditions. Confirm only with a harmless synthetic resource operation when separately in scope; simulation is not execution proof.

3. Trace reachable authority changes such as policy edits, role delegation or passing a role to an allowed service. Establish every required permission and service constraint statically; a wildcard in isolation does not prove a usable escalation path.

4. Narrow the evidenced authority at the appropriate policy boundary and preserve needed service behavior. Reevaluate denied and required tuples, alternate session/resource principals and the original deployment context after change.

## Evidence decisions

A permissive-looking policy fragment is not the complete effective permission set. Missing policy layers or simulator support must remain uncertainty, and broad administration may be explicitly intended.

Provide sanitized principal/session form, action/resource/context tuple, applicable policy snapshots and versions, evaluation path, missing layers, intended role contract and any bounded observed operation.

Report an affected customer deployment to its owner under its policy; do not route ordinary customer IAM configuration to AWS as a provider vulnerability.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **AWS IAM policy semantics; do not flatten into a generic allow/deny union**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
