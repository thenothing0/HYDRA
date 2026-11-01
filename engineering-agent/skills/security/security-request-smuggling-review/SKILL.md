---
name: security-request-smuggling-review
description: "Review HTTP framing, request boundaries and proxy/backend disagreement. Use for authorized request-smuggling analysis, preferably in isolated replicas."
---

# HTTP request desynchronization

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map client, CDN/proxy, protocol translation, backend parsing and connection reuse. Obtain actual versions/configuration and distinguish parsing differences from ordinary request rejection.

2. Use an isolated two-hop local fixture or source/configuration evidence to compare request-boundary interpretation. Any live verification must already authorize connection-state testing and keep other users out of the connection pool.

3. Correlate labeled requests across both hops, including protocol downgrade and error recovery. Stop on unexpected cross-request interference; do not use long delays or shared-queue exploitation against unrelated traffic.

4. Resolve disagreement through supported consistent parsing and rejection/connection handling. Retest legitimate pipelining/translation and prove request boundaries remain aligned across errors.

## Discrimination and evidence

A timeout or status difference alone does not establish smuggling. Source review without a representative intermediary stack leaves runtime exploitability unresolved.

Provide hop/protocol topology, redacted paired traces or parser proof, connection isolation, interpretation discrepancy and tested impact; do not claim session takeover from a framing signal alone.


## Classification and reporting

The initial planning lens is OWASP A02:2025 and CWE-444; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://portswigger.net/web-security/request-smuggling) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
