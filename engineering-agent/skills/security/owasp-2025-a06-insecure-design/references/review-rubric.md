# Review acceptance rubric

Use this to critique an assessment before delivery, not to assign a marketing score to the skill.

| Gate | Accept | Return for correction |
|---|---|---|
| Scope | Actual target/build, allowed action and controlled identity are clear | Assumed permission, unknown deployed build hidden, unrelated target added |
| Intended rule | Requirement or code-supported boundary is explicit | Assumed business rule, generic checklist claim |
| Reachability | Registered entry point/caller trace or actual scoped observation | Uncalled helper, unused dependency, example config |
| Security effect | Protected data/authority/state or material availability consequence evidenced | Status difference, exception, scanner label alone |
| Discrimination | Legitimate/public/compensated alternative considered | Public data treated as private, unread internal logs treated as absent |
| Evidence | Minimal reproducible trace, version/context, saved artifact and limitations | Secret spill, unrelated records, missing prerequisites |
| Severity | Contextual rationale separates observed and plausible impact | Historical CVE rating copied, unverified chain presented as takeover |
| Remediation | Authoritative fix preserves valid behavior and deployment/migration considered | UI workaround, WAF-only closure, manifest-only upgrade claim |
| Closure | Original failure prevented; allowed control and state effects checked on fixed build | Patch text only, retest on another build, missing side-effect check |
| Coverage | Untested/nonapplicable boundaries have reasons | No findings stated as whole-category security |

The local fixture tests and workflow-tool regression suite do not constitute a blinded model evaluation. Do not calculate detection precision/recall from tests that simply compare deliberately insecure and guarded implementations. For a future model evaluation, separate task inputs from assessor-only ground truth, run without expected answers, score observed findings and missed/false claims, and record model/settings/tools/commit. Such a run remains not performed unless actual transcripts and outputs exist.
