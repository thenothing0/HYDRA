---
name: security-api-resource-limits-review
description: "Review API cost admission, quotas and rate-limit keying. Use bounded source/local cost analysis, not live denial-of-service or password spraying."
---

# API resource consumption and abuse limits

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map expensive operations, accounting identities, pagination/batching, concurrency and downstream spend. Establish the intended resource/abuse budget from product or owner evidence.

2. Inspect admission counters, key normalization, enforcement order and atomicity. Use a deterministic local fixture or a small explicitly agreed test budget to measure attempts/cost without stressing a live service.

3. Review alternate methods/channels, anonymous versus authenticated attribution, retry behavior and whether rejection occurs after expensive work. Distinguish authentication controls from general resource limits.

4. Apply limits at the effective cost boundary with appropriate identity/window behavior. Retest permitted workload, bounded over-budget rejection and recovery without unintended user lockout.

## Evidence and discrimination

One unthrottled request or absence of a rate-limit header is not a demonstrated resource vulnerability. Do not infer business loss without supported cost/limit information.

Include required budget, attribution/enforcement trace, bounded measurement method, actual resource consequence and legitimate workload control.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A06:2025 and CWE-770; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
