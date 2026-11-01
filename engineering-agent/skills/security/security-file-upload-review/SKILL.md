---
name: security-file-upload-review
description: "Review upload validation, storage, retrieval and downstream file processors. Use for unsafe upload execution, content handling, ownership and archive-processing boundaries."
---

# Unsafe file upload and processing

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Map filename/type/size checks through storage key generation, permissions, scanning/processing, public retrieval and alternate import paths. Identify the dangerous consumer, not merely acceptance of an extension.

2. Use benign uniquely labeled fixtures to check content/type disagreement, path handling, attachment headers and retrieval permissions. Inspect server interpretation or a local processor stub instead of uploading a live web shell.

3. For archives, trace canonical extraction paths, link handling and expanded-size limits using bounded local fixtures. Review deferred jobs, conversion services and cleanup as distinct trust boundaries.

4. Fix validation and the storage/consumer boundary together. Verify permitted documents still process, unauthorized reads fail, executable interpretation is absent where forbidden and rejected uploads leave no unintended artifacts.

## Discrimination and evidence

An accepted file extension or controllable Content-Type alone does not prove execution. Public upload may be intended; demonstrate a prohibited interpretation, access or processing effect.

Record uploader/retriever roles, benign fixture identity, effective storage/serving policy, downstream processor, response interpretation and owner-side artifact/cleanup checks.


## Classification and reporting

The initial planning lens is OWASP A06:2025 and CWE-434; these are analyst hints, not a mandatory mapping for every defect in this technology. Choose the final category/CWE from the actual root cause and current primary reference. [Controls and coverage](assets/control-catalog.json) are planning guidance, not execution results.

Write one report per independent finding using [finding-template.md](assets/finding-template.md). Include prerequisites, reproducible steps or a complete source trace, expected/observed behavior, actual impact, confidence/limits and remediation. Do not inflate unverified escalations. Related findings can be linked without merging independent causes.

For destination discovery, use the published owner policy and program scope, never infer the receiving program from an asset’s hostname alone. If the optional reporting skills are installed, request security-disclosure-routing and security-platform-report. Otherwise follow [report-handoff.md](references/report-handoff.md) manually. Preparation alone does not authorize sending a report.

## Primary reference

[Technical source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) — retrieved 2026-10-27. Read the sections relevant to the actual implementation; verify version-sensitive details before deciding. No real target was assessed while authoring this skill.
