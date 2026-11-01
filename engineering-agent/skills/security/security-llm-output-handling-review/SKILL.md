---
name: security-llm-output-handling-review
description: "Review generated model output passed to HTML, queries, code, files or command consumers. Use for improper output handling with an evidenced downstream sink."
---

# LLM output consumed by interpreters and renderers

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. The [runtime contract](references/runtime-contract.md) supports agents with different tools; the core workflow requires no vendor API or sibling skill. Establish target, permission and evidence availability before claiming checks.

## Investigation

1. Trace generated text/structured fields, parser repairs and streaming fragments into the final renderer, interpreter or file consumer. Record the specific context and whether the service treats generated data as trusted structure or instructions.

2. Stub the model response with an inert context-changing marker and exercise the actual consumer in isolation. Compare a legitimate generated value and observe the parser/argument/DOM result; a deterministic stub tests the sink, not the live model's probability of producing it.

3. Review streamed versus final output, retries, fallback parsers, schema coercion and tool-result display. Determine whether user or retrieved input can plausibly influence the candidate field, keeping reachability distinct from sink proof.

4. Apply context-appropriate data APIs, constrained structure and output handling at the consumer. Retest valid generated content, malformed/extra structure, streaming/fallback paths and the original sink effect; model prompting alone is insufficient assurance.

## Evidence decisions

An alarming string in a chat answer is not code execution. Schema-valid JSON does not establish that fields are safe for a shell, SQL expression or HTML context.

Include producer influence, exact generated-field-to-sink path, consumer context, stub versus live-model evidence, inert downstream effect and valid-output control.

Route a confirmed SQL/XSS/command defect to the corresponding technique report and link the model ingress; avoid duplicate reports for the same root cause.

Separate confirmed findings from source-supported concerns and unverified hypotheses. Record the missing decisive check and any inaccessible policy/runtime layer. Stop active verification on unexpected exposure, unrelated state changes or degradation; preserve minimal redacted evidence and continue statically where useful.

## Reporting and remediation acceptance

Write one report per independent root cause using [finding-template.md](assets/finding-template.md), including affected build/configuration, prerequisites, expected versus observed behavior, contextual severity and limits. Retest the original failure and permitted control before closing the fix. Related ingress paths sharing the same defect belong in the same report; describe distinct defects and their chain explicitly.

Read [report-handoff.md](references/report-handoff.md) when preparing disclosure. If available, security-finding-report separates findings, security-disclosure-routing verifies the affected owner's policy/scope/channel, and security-platform-report adapts the draft to the actual program template. Preparation does not imply permission to send it. A deployment defect belongs to the affected deployment's owner unless evidence establishes a provider product defect.

## Taxonomy and references

Native context: **OWASP LLM05:2025; classify the actual downstream injection boundary separately**. The catalog's OWASP A05:2025 field is only a compatibility/planning lens for the existing assessment helper. It is not a normative crosswalk from mobile/cloud/AI to the web Top 10. Select final taxonomy and any CWE from the demonstrated root cause; leave an unsupported mapping unassigned.

[Control catalog](assets/control-catalog.json) and [review cases](assets/review-cases.json) are authored planning/evaluation inputs, not performed target tests. Cases describe what sufficient and insufficient evidence would look like.

[Primary reference](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) — accessed 2026-10-27. Apply current provider/runtime-specific guidance to version-sensitive decisions. Source access is not an exhaustive survey of public reports or proof that a target has the defect.
