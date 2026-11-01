# Offline reporting contract

Use Python 3.10+ only if the optional helper is useful. Copy assets/finding-input.json into the task working directory, populate it from evidence, and save redacted artifacts beside it. No target or route evidence is prefilled as verified.

```text
python "<skill-root>/scripts/security_reports.py" check "<work-root>/findings.json"
python "<skill-root>/scripts/security_reports.py" bundle "<work-root>/findings.json" --output "<work-root>/reports-new"
```

The output directory must not already exist. Each opaque finding ID becomes its own directory with report.md, submission-fields.json, route.json, attachments/ and routing-evidence/. index.json links the reports and flags supplied shared root-cause IDs. No files are sent anywhere; the helper imports no network client.

## Finding input

schema_version is 1.0 and findings is an array. Each finding needs an opaque id; title, asset, vulnerability, summary, preconditions, expected, observed, impact, root_cause, remediation, severity_rationale and confidence as nonempty text; status (confirmed, suspected, unverified, patched-unverified, fixed or not-reproduced); severity (critical, high, medium, low, informational or undetermined); content_reviewed true after manual secret/privacy review. steps is an array of reproduction text; requests can contain redacted HTTP/code text; limitations explains actual coverage. The helper does not translate text automatically.

evidence items require id, relative path, actual lowercase sha256, redacted true, and optional description. Files must stay within the input folder; hashes apply after redaction. Evidence is copied only into its own report. Content review flags are assessor assertions; the script cannot detect every secret or verify a claim is true.

Optional root_cause_id flags possible duplicate causes; related_findings links independent IDs without merging. Optional cwe, vrt, cvss, asset_type and program_fields carry only evidence-supported selections. These fields are not automatically calculated or semantically verified.

## Route input

The route object contains status, platform (hackerone, bugcrowd, intigriti, yeswehack or vendor), the exact finding asset, program_status, ownership_verified, asset_in_scope, vulnerability_in_scope, access_verified, scope_rationale, checked_at and submission_url. Optional required_custom_fields lists live-form requirements; values belong in finding.program_fields. Published direct contact mailto is supported only for vendor; the tool never sends it.

sources is an array of local reviewed/redacted policy evidence: role (owner-policy, program-policy or pointer), public HTTPS source url, checked_at with timezone, relative path, sha256 and redacted true. A platform route needs owner-policy and program-policy evidence; a direct vendor route needs owner-policy. These are declarations that a reviewer must substantiate from actual current official sources. No domain lookup/owner inference occurs in the helper.

## Blockers and limitations

An unverified route, exact-asset mismatch, unsupported scope/access/owner assertion, nonactive program, missing source evidence, platform-domain mismatch, required custom field, unresolved severity, uncertain finding, insufficient steps/evidence or absent limits keeps the output needs-review. Route/source timestamps older than seven days are stale for this helper; always recheck the live policy just before an authorized submission regardless of that threshold. complete-fields-route-documented means structural declarations are present, not submission-ready truth or acceptance.

For a saved contact pointer, run:

```text
python "<skill-root>/scripts/security_reports.py" securitytxt "<work-root>/security.txt" --output "<work-root>/pointer.json"
```

This extracts limited fields and flags missing/multiple/expired Expires or missing Contact. It is not a full RFC/signature/origin validator. A fresh pointer is only candidate information and never grants testing authorization. Do not use it as owner/program scope evidence by itself.

The example input contains one intentionally incomplete, unreviewed item. Fill it from actual evidence or remove it; the helper correctly rejects it as a distributable bundle until its required text and review assertions are supplied. Do not flip booleans merely to bypass missing verification.
