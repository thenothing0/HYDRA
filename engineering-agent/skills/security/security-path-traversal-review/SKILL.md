---
name: security-path-traversal-review
description: "Review user-controlled filesystem paths, downloads, extraction and canonical-path enforcement. Use for traversal and link-related escapes from an intended file root."
---

# Path traversal and unsafe file access

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace external path components through decoding, normalization, joining, canonicalization, authorization and open/read/write operations. Identify the intended root and whether links or archives can change resolution.

2. Create a local allowed directory and a harmless outside sentinel. Compare normal access, a denied escape and alternate entry points without reading host secrets or unrelated files.

3. Inspect absolute-path handling, platform separators, symbolic links and time-of-check/time-of-use behavior where applicable. A string prefix comparison may differ from an actual resolved containment check.

4. Enforce containment and access at the actual file operation, with platform-correct semantics. Retest outside sentinel denial, owner permissions, valid filenames and absence of partial writes.

## Discrimination and evidence

A reflected path, unusual filename or generic file-not-found response is not proof of outside-root access. Establish the file actually opened and the policy it violates.

Include intended root, normalized/resolved path trace, disposable sentinel contents, caller permissions and read/write effect. Separate traversal from broader file-read authorization issues.


## Classification and reporting

The initial planning lens is OWASP A01:2025 and CWE-22; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://owasp.org/www-community/attacks/Path_Traversal) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
