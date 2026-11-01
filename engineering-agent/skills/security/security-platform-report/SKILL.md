---
name: security-platform-report
description: "Prepare a single-finding report and field handoff for HackerOne, Bugcrowd, Intigriti, YesWeHack or a verified direct VDP. Use an established route and current program template; drafts only unless submission was explicitly authorized."
---

# Platform-specific finding report

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Use the verified owner/program route and normalized finding to generate the profile appropriate to that recipient. Read [platform-profiles.md](references/platform-profiles.md) and [report-contract.md](references/report-contract.md). The local helper creates Markdown and human-handoff fields, not undocumented API payloads. [Runtime contract](references/runtime-contract.md) applies across agents.

1. Recheck the receiving program’s current template, asset choice, vulnerability taxonomy/severity method, preferred language and custom required fields. Its actual form overrides generic platform guidance. Keep private program details with their intended recipient.
2. Map supplied evidence to title, affected asset/endpoint, prerequisite actor/setup, reproducible steps and redacted HTTP, expected/observed results, actual impact, remediation and limits. Keep the report understandable without relying on a video or screenshot as the only reproduction.
3. Use the current evidence-supported CWE/VRT/CVSS selection as applicable. Do not calculate a CVSS score from a severity label or automatically equate Bugcrowd priority with a CVSS band. Flag unknown taxonomy/custom fields instead of guessing.
4. Produce exactly one report folder per independent input finding, with only its own redacted evidence, route record and selected platform fields. Preserve related issue IDs and potential shared causes for review. Do not produce several platform submissions for the same issue unless the user explicitly requests alternatives as drafts.
5. Review missing evidence, eligibility, access and route freshness. A locally complete record is not proof of program acceptance or factual validity. If routing is unresolved, retain a neutral or explicitly requested platform draft with blockers.

Use the offline bundle command in the contract to generate files when appropriate. It has no network/submission capability. An actual external draft, email, message or final submission requires the user’s explicit authorization for that action; preserve any authorization already given rather than asking again. This skill never infers permission to transmit from a request to write a report.



For a cross-cutting evidence decision, consult the [family guide](references/decision-playbook.md) only when useful.
