---
name: security-ssrf-review
description: "Review authorized server-side URL fetchers, preview/import services, webhooks and destination policy for SSRF. Use for fetch trust boundaries rather than broad network discovery."
---

# Server-side request forgery

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map every fetch entry point and identify whether the caller controls scheme, host, port, path, redirects or resolution. Trace normalized destinations and the network egress rule at the actual connection.

2. Define allowed destinations from the product contract. Compare a permitted owned endpoint with a forbidden local/owned fixture, then verify redirect hops and any re-resolution. Retain a labeled callback event rather than unrelated response data.

3. Inspect alternate URL parsers, address representations, proxy settings and worker fetch paths. Prefer source review/local stubs for internal-address checks; do not probe cloud metadata or unrelated internal services.

4. Repair destination enforcement at each relevant hop/connection and verify both denied callbacks and the legitimate import. Separate a confirmed request from unverified internal-service reachability or data extraction.

## Discrimination and evidence

A supplied URL, an error, DNS lookup alone or a public fetch feature is insufficient. Show that an actual server request crosses the documented destination boundary.

Include controlled callback identity/timestamp, original and redirect destination decisions, resolver/egress context, and exactly which reachability or response disclosure was demonstrated.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-918; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
