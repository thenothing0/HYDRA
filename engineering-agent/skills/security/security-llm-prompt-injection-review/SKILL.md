---
name: security-llm-prompt-injection-review
description: "Review direct/indirect prompt injection in an authorized LLM application. Use for external content promoted to instructions and measurable task or authority violations."
---

# LLM application instruction and data boundary

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Map user instructions, retrieved documents, tool results, attachments and persisted memory to prompt assembly and downstream tools. Define the application's allowed task and protected data/action boundary before selecting a test.

2. Use a small owner-approved corpus with harmless canaries or stub actions and benign task controls. Test whether lower-trust content changes the protected outcome, recording trials, model/settings and full sanitized interaction; no harmful-content safeguard bypass is needed.

3. Separate instruction-following deviation from unauthorized tool execution, data disclosure or sink injection. Inspect deterministic authorization and data restrictions outside the model; retrieval text and a model-based guard are both lower-trust inputs.

4. Reduce untrusted instruction authority and enforce tool/data permissions independently of generated text. Retest the failing fixture and benign tasks within a stated budget; describe observed regression results without claiming a universal prompt-injection cure.

## Evidence decisions

A model repeating document text, a harmless answer variation or a prompt-like string is not by itself the claimed security impact. A failed attack in a few runs cannot prove immunity.

Include authorized task and boundary, controlled content placement, sanitized prompt/tool trace, canary/stub effect, model/configuration, attempts and controls, and actual versus proposed downstream impact.

Limit evaluation to the owned application's task/data/authority boundaries; do not create jailbreak optimizers or seek harmful model outputs.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **OWASP LLM01:2025; web Top 10 lens is optional planning compatibility only**. The catalog's OWASP A06:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
