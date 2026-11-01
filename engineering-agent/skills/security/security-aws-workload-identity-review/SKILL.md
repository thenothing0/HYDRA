---
name: security-aws-workload-identity-review
description: "Review AWS workload federation from CI or other OIDC issuers into IAM roles. Use for issuer/audience/subject trust and repository, environment or workload binding."
---

# AWS workload OIDC role trust and claim binding

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map the trusted issuer/provider, role trust policy, audience and provider-specific subject/claim format to the intended workload identity. Record repository/ref/environment or cluster/service-account conditions from current issuer guidance.

2. Compare authorized and wrong-workload claim fixtures with the actual trust conditions. Keep mock claim evaluation distinct from STS verification; use genuine tokens only from owned test identities and avoid storing them in evidence.

3. Inspect reusable workflows, environment protections, renamed identities, wildcard subjects and which principal can edit the trusted job. Separate ability to assume the role from the role's resulting permissions and session constraints.

4. Bind federation to the intended issuer and workload conditions and narrow role authority. Retest a valid workload, wrong audience/subject and relevant alternate workflow context without changing production trust during assessment.

## Evidence decisions

OIDC use, temporary credentials or a broad-looking subject pattern alone do not prove unauthorized role assumption. The issuer must actually issue the required signed claims to the claimed actor.

Include trust-policy snapshot, issuer claim contract, intended workload and attacker-controlled counterpart, condition evaluation, token redaction, actual versus simulated result and resulting role authority limits.

Do not acquire another organization's identity or use exposed tokens; customer trust-policy defects belong to the affected deployment owner.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **AWS STS web-identity role trust; not end-user OAuth login**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
