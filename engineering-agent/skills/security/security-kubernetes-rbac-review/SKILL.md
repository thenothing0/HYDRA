---
name: security-kubernetes-rbac-review
description: "Review Kubernetes Roles, bindings and service-account authority. Use for namespace/cluster privilege, workload delegation and sensitive API verbs."
---

# Kubernetes RBAC and delegated workload authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Build the subject-to-binding-to-rule graph for the relevant namespace and cluster. Record groups, aggregated roles, resource/subresource and verb scope, other authorizers and the intended operational role.

2. Prefer sanitized manifests and authorized read-only access checks for specified tuples. In a disposable namespace, use synthetic objects to verify a relevant denied/allowed pair only if needed. Do not enumerate or dump actual Secrets for proof.

3. Trace workload creation, service-account selection, bind/escalate/impersonate and control over admission-relevant resources against actual cluster constraints. Distinguish a static escalation hypothesis from a reachable granted capability.

4. Reduce the evidenced binding/rule or delegated authority without altering required system roles blindly. Retest required API calls and forbidden namespace/cluster actions, including all grants to the subject.

## Evidence decisions

A ClusterRole definition alone gives no subject permission without a binding. Namespace-scoped workload creation may delegate additional authority, but the actual admission/runtime restrictions need review.

Record subject/groups, namespace, complete applicable binding/rule path, cluster/version context, exact verb/resource tuple, other controls and static-versus-observed authority with a required-use control.

Do not create privileged pods, impersonate administrators or mount real credentials merely to demonstrate an RBAC concern; use static analysis or an isolated replica.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **Kubernetes authorization; RBAC permissions are additive and deployment-dependent**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
