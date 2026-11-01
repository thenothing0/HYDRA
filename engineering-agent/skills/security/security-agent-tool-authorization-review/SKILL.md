---
name: security-agent-tool-authorization-review
description: "Review AI agent tool calls against user, tenant and action authority. Use for excessive capability, confused delegation and approval-to-action binding."
---

# AI agent tool capability and delegated authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map tool schemas, credentials, resource selectors and execution services to the current user's permitted actions. Identify whether model-selected identifiers or retrieved content can choose another actor, tenant or privileged operation.

2. Use an in-memory tool ledger or owned sandbox resources to submit a valid and prohibited call at the actual gate. Compare direct tool invocation with model-generated invocation; a refusal in chat does not prove enforcement in the execution service.

3. Trace delegated agents, async tasks, retries and approval objects to the exact action/resource/parameters executed. Check changes after approval, duplicate commitment and credential reuse without assuming every product requires the same confirmation policy.

4. Constrain tool functionality and enforce actor/resource/action permissions outside the model. When the product requires approval, bind it to immutable reviewed parameters and appropriate lifetime; retest required actions, denied cross-authority calls and replay/change cases.

## Evidence decisions

Tool availability is not automatically excess authority, and a model proposing a forbidden action is not execution. The finding requires a violated application permission or approval contract.

Provide user/tool authority contract, credential identity, exact sanitized call and resource, gate/approval trace, stub ledger or actual bounded effect and permitted-call control.

Use stub mail/payment/deletion tools for verification. Writing a draft or reviewing a tool does not authorize real external messages, purchases or destructive actions.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **OWASP LLM06:2025; verify authority at the tool/service boundary**. The catalog's OWASP A01:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
