---
name: security-host-header-review
description: "Review Host/forwarded authority used for sensitive links, routing or caching. Use for host-header trust failures without broad virtual-host discovery."
---

# Host and forwarded-origin trust

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map ingress/proxy trust and the application’s authority source for absolute URLs, tenant routing, redirects and cache keys. Separate the received value from the trusted configured public origin.

2. Use a controlled fixture host and owned sink to observe a generated link or routing decision. For recovery flows use a private test inbox and never send real tokens to an external endpoint.

3. Inspect override headers and alternate proxy/direct paths only within the actual deployment model. Do not brute-force unrelated virtual hosts or internal services.

4. Repair origin/routing authority at its configuration or trust boundary and reject unrecognized values as appropriate. Retest intended domains/proxy hops and the original sensitive consumer.

## Evidence and discrimination

Header reflection or an absolute link alone is insufficient. Establish a prohibited security consequence; reset poisoning, cache influence and routing SSRF are distinct claims.

Provide ingress topology, trusted versus caller-controlled authority, actual generated link/route effect, allowed-host control and any unverified escalation.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A02:2025 and CWE-20; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://portswigger.net/web-security/host-header) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
