---
name: security-subdomain-takeover-review
description: "Review dangling DNS and third-party resource binding for authorized subdomain-takeover assessment. Use passive evidence and provider ownership controls."
---

# Dangling DNS and service ownership

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Resolve the exact in-scope hostname and documented owner, DNS chain and service provider. Correlate with the provider’s current resource-binding/verification model.

2. Use public DNS/HTTP evidence and owner-supplied cloud state. A missing resource fingerprint is a hypothesis; determine whether the name is actually claimable under current provider controls.

3. Do not register, claim, bind or publish content on the organization’s name merely to strengthen a report unless that action is already explicitly authorized. Use a local/provider test account fixture for behavior where possible.

4. Remove or repair stale DNS/resource bindings and verify the intended service plus deprovisioning lifecycle. Assess cookie/CSP/phishing implications separately from proven hostname control.

## Discrimination and evidence

NXDOMAIN, a CNAME or a provider error page alone does not prove takeover. Provider verification and reservation can make a dangling pointer unclaimable.

Include hostname scope/ownership, DNS chain and timestamps, provider control evidence, claimability limits and the confirmed or suspected status; do not fabricate control proof.


## Classification and reporting

The initial planning lens is OWASP A02:2025 and CWE-16; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
