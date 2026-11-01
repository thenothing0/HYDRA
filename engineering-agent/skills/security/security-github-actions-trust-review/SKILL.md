---
name: security-github-actions-trust-review
description: "Review GitHub Actions workflows where untrusted events or code reach privileged jobs. Use for event-to-checkout trust, script interpolation, tokens and runner persistence."
---

# GitHub Actions event, checkout and runner trust

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Trace event-controlled fields and checked-out revisions through expressions, scripts, actions and reusable workflows. Record event type, fork/trust context, token permissions, environment gates and runner ownership per job.

2. Use static expansion analysis or a detached local stub to show data becoming script/instructions or untrusted code entering a privileged job. If a workflow run is needed, use an owned sandbox repository with no secrets or write token; do not open test PRs against third parties.

3. Review trigger transitions, privilege-bearing follow-up jobs, persisted self-hosted runner state and who can alter action dependencies or workflow code. Distinguish an untrusted build with no sensitive capability from a protected release/deployment path.

4. Separate untrusted execution from sensitive credentials/runners, pass external values as data and grant only required job authority. Retest the intended contributor workflow, denied trust crossing and actual checked-out revision.

## Evidence decisions

A dangerous-sounding event or use of an external action alone does not prove compromise. Demonstrate attacker-controlled input/code meeting a specific privileged consumer under the configured gates.

Include workflow revision/lines, event/actor control, resolved checkout, interpolation or dependency path, effective job authority/gates, runner state assumptions and inert proof versus static hypothesis.

Repository administration and external CI execution are separate permissions; assessment does not authorize modifying live workflows or publishing releases.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **GitHub Actions event/permission semantics; recheck repository configuration**. The catalog's OWASP A03:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://docs.github.com/en/actions/reference/security/secure-use) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
