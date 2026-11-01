---
name: security-oauth-oidc-review
description: "Review OAuth/OIDC authorization, callback binding and account-linking flows. Use for federation identity confusion and token/session trust contracts."
---

# OAuth/OIDC and account linking

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map client/provider roles, registered redirects, authorization request state, nonce/PKCE where applicable, code redemption, validated claims and local account linkage.

2. Use controlled identities and a dedicated provider/client fixture. Change one session, redirect or linking property and record whether the returned authority binds to the intended actor and browser session.

3. Inspect alternate providers, email verification semantics, linking/unlinking/recovery branches and replay. Do not send real authorization codes or tokens to third-party endpoints.

4. Repair the supported protocol flow and local identity mapping. Verify normal federation, rejected wrong-session/callback/claims and persistence of required MFA or account controls.

## Discrimination and evidence

A similar email string, readable token or redirect alone does not prove takeover. Distinguish authorization code delivery, token use and local authenticated authority.

Include provider/client context, registered redirect evidence, redacted state/code flow, claim/account binding, controlled identities and the exact identity consequence.


## Classification and reporting

The initial planning lens is OWASP A07:2025 and CWE-287; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
