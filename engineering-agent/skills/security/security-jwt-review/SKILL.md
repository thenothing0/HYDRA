---
name: security-jwt-review
description: "Review JWT trust validation and token lifecycle across languages. Use for algorithm/key confusion, issuer/audience/purpose checks and revocation behavior."
---

# JWT validation and token lifecycle

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace token issuance and every protected-path validator: allowed algorithms, trusted key origin, issuer, audience, token purpose, time handling and conversion to local privileges.

2. Use locally issued synthetic tokens to vary one property at a time. Confirm rejection on the real protected code path and retain a valid token control without storing live bearer values.

3. Inspect alternate validators, refresh/recovery tokens, cache/key rollover and documented revocation. Ensure an untrusted token cannot select an unauthorized key source or be accepted for another purpose.

4. Fix central validation using supported library APIs and explicit policy. Retest wrong authority/claims, expired and intended tokens, plus the selected lifecycle/revocation model.

## Discrimination and evidence

Base64-decodable claims are expected. A malformed token rejection does not test acceptance of a validly signed but wrong-purpose token; logout behavior depends on the declared policy.

Document validator/library configuration, trusted key source, claim contract, exact accepted/rejected synthetic cases and which privilege was actually granted.


## Classification and reporting

The initial planning lens is OWASP A07:2025 and CWE-347; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
