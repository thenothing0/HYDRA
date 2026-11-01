---
name: security-ldap-injection-review
description: "Review LDAP filter/DN construction and directory-query boundaries. Use for LDAP injection with context-specific APIs and controlled directory fixtures."
---

# LDAP filter and distinguished-name injection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Locate directory lookups and bind/search flows. Trace external values into filter expressions, distinguished names, base DNs and attribute selection; these contexts need distinct handling.

2. Use a local directory fixture or query instrumentation with synthetic entries. Compare a literal name containing special characters with a candidate that changes query structure; avoid enumerating a real directory.

3. Inspect concatenation in helper methods and identity mapping after a search result. Establish whether extra matches change authentication/authorization or merely a permitted search feature.

4. Use supported context-appropriate escaping/builders and constrained search structure. Retest valid special-character names, expected search scope and denied structural changes.

## Evidence and discrimination

Filter syntax in a string or a directory error does not prove an effective injection. Escaping rules for a DN are not interchangeable with search-filter encoding.

Document filter versus DN context, directory API/feature, caller-controlled component, synthetic match/identity consequence and a valid-name control.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-90; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
