---
name: security-kubernetes-workload-isolation-review
description: "Review Kubernetes pod admission and security context across containers. Use for host mounts/namespaces, privilege, capabilities and enforced workload isolation."
---

# Kubernetes workload admission and host isolation

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Inspect rendered/admitted pod specifications for app, init and ephemeral containers, host interfaces, mounts and service-account identity. Record actual cluster version, node OS/runtime and intended trust separation.

2. Compare a normal workload with a prohibited synthetic specification using policy evaluation or authorized server dry-run. Distinguish warning/audit from enforcement and verify whether mutation changes the admitted object; a dry-run is not runtime isolation proof.

3. Review policy exemptions, namespace-label editors, controller templates, capability/security-context overrides and host resource exposure. Evaluate network isolation separately from Pod Security Standards and avoid treating a namespace as a complete sandbox.

4. Enforce the appropriate admission profile and runtime restrictions for the workload, with documented justified exceptions. Retest valid deployment, rejected prohibited specification and the final admitted configuration on relevant OS/version combinations.

## Evidence decisions

Absence of one hardening field is not automatically a container escape. A privileged workload can be intentional; establish who controls it and what protected boundary is weakened.

Include rendered and admitted spec, controller/namespace context, policy enforcement/exemptions, node OS/runtime/version, lower-trust editor capability and precise static or observed host-access consequence.

Do not run escape payloads or access the host filesystem on a shared cluster; bounded admission checks and a local replica are sufficient for initial evidence.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **Pod Security Standards; choose the applicable Kubernetes version and OS**. The catalog's OWASP A02:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://kubernetes.io/docs/concepts/security/pod-security-standards/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
