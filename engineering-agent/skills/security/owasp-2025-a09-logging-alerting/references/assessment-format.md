# Structured assessment format — schema 1.0

The checker accepts one JSON object, not a vulnerability verdict. Start with the linked template and replace empty fields with actual observations. A zero-finding assessment is valid when coverage is explicit. Never prefill confirmations or mark evidence redacted without reviewing it.

## Assessment

`schema_version`: `1.0`; `run_id`: opaque run label; `category`: A01 through A10; `mode`: code-review, bug-bounty or mixed. `target`, `authorization` and `limitations` are nonempty strings describing actual context. These statements are asserted by the assessor, not verified permission or deployment identity.

`evidence`, `coverage`, and `findings` are arrays. Every item has a unique `id` within its array, using 1–64 ASCII letters, digits, underscores or hyphens. Cross references use these IDs. Do not put personal data or tokens in them.

## Evidence item

Required: `id`, `path`, `sha256`, `kind`, `description`, `collected_at`, `redacted`.

- `path` is a relative existing file inside the assessment's directory; parent traversal and links resolving outside are rejected.
- `sha256` is the actual lowercase hex SHA-256 of the delivered redacted file's bytes. If redaction changes a file, hash it afterwards and describe the transformation. Keep any raw material private.
- `kind` is code-trace, http-metadata, test-output, configuration or other.
- `collected_at` uses ISO 8601 with a timezone offset, such as `2026-10-27T09:00:00+03:00`; use the actual time/offset, not this example.
- `redacted` must be the boolean true after review. The checker does not inspect content for secrets.

## Coverage item

Required: `id`, `boundary`, `status`.

- `tested` also needs nonempty `evidence_ids` and a `result` with observed behavior. A source inspection can be tested coverage when labeled accurately.
- `not-tested` and `not-applicable` need a specific `reason`.

Use the [coverage starter](../assets/coverage-starter.json) only as a starting outline; replace its generic boundaries with the actual paths and controls.

## Finding item

Required nonempty strings: `title`, `expected`, `observed`, `preconditions`, `impact`, `root_cause`, `remediation`, `severity_rationale`, `confidence`. Also include `id`, matching `category`, `status`, `severity`, `evidence_ids` and nonempty `coverage_ids`. Optional `cwe` uses a supported `CWE-number`; omit if unmapped rather than guessing.

- Status: confirmed, suspected, unverified, patched-unverified, fixed or not-reproduced.
- Severity: critical, high, medium, low, informational or undetermined. Contextual rationale is always required.
- Confirmed/fixed requires nonempty evidence, at least one tested referenced boundary, and explicit `reachability` and `false_positive_check` explanations.
- Patched-unverified requires evidence, but makes no tested-fix claim.
- Fixed additionally requires `fixed_build` and `retests`. Include passing negative, positive and side-effect controls. Each has `kind`, `result`, `tested_build` matching the fixed build, nonempty `expected`, `observed` and `evidence_ids` referencing execution evidence (test-output or http-metadata). One artifact may contain multiple controls if their outcomes are distinguishable.

More application-specific detail can accompany the record, but the helper does not validate arbitrary added fields. CVSS calculation and program submission are not automated. A well-formed lie can pass a structural checker; review the actual evidence and reasoning.
