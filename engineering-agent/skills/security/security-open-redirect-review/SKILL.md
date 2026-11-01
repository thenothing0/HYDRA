---
name: security-open-redirect-review
description: "Review untrusted redirect/forward destinations and sensitive-flow chaining. Use for destination validation, URL normalization and trusted callback boundaries."
---

# Redirect destination validation

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace redirect parameters and server/client forwards through decoding, normalization, relative-path handling and destination policy. Identify the role of redirects in login/recovery/federation.

2. Use an owned benign destination and a permitted local-path control. Record the actual final destination without sending live credentials or codes externally.

3. Inspect allowlist comparisons and alternate flow endpoints. Treat phishing or OAuth escalation as separate claims that require the relevant trust/token leakage evidence.

4. Prefer constrained destinations or trusted server-side mappings and verify normal navigation. Retest disallowed destinations after normalization and at the actual redirect sink.

## Discrimination and evidence

A link to an external site or an intentionally external navigation feature is not automatically a security issue. An open redirect does not by itself establish token theft or account takeover.

Provide policy, caller control, actual redirect target, normalization trace, affected flow and bounded demonstrated consequence.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-601; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
