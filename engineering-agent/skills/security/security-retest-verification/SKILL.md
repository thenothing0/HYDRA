---
name: security-retest-verification
description: "Verify a supplied finding after remediation and draft a retest outcome. Use for fixed/still-reproducible/blocked/inconclusive evidence, build identity and regression controls; does not change platform state."
---

# Evidence-based remediation retest and closure

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Use [runtime-contract.md](references/runtime-contract.md) for missing tools and host-independent operation. Read [report-contract.md](references/report-contract.md) for the output/evidence boundary, then use [followup-template.md](assets/followup-template.md).

Begin with the original finding, accepted root cause, evidence and requested retest scope. Establish the changed build/configuration and available test identity. A platform invitation or patch description supplies context; preserve the actual testing authorization and limits.

1. Reconstruct the original preconditions and prohibited behavior. Distinguish changed data, expired accounts, feature removal and genuine enforcement. If the original setup cannot be reestablished, record why rather than treating non-reproduction as a fix.
2. Exercise the original failing path with synthetic data in the authorized environment. Record a permitted control and relevant state/side-effect checks on the same build. Prefer the smallest decisive retest; additional bypass discovery is separate scope and may be a separate finding under the program policy.
3. Review the patch/configuration path where available, alternate originally affected entry points and required migration/deployment state. Static repair review alone is patched-unverified; a 403/error response alone is insufficient if the operation already committed.
4. Produce one retest record per finding using the linked template. Separate technical outcome from platform status: fixed requires sufficient retest evidence and valid controls; still-reproducible needs the observed failure; blocked/inconclusive states the missing decisive check. A platform may use different labels and manual resolution rules.

Do not close a report, accept a paid retest, post a comment or submit findings merely because this skill prepared a draft. Use the live program instructions if an external action is explicitly authorized. Keep evidence isolated per finding and redact/hash delivered artifacts after review.

[Review cases](assets/review-cases.json) are authored decision scenarios, not executed evaluations. [Primary platform reference](https://docs.hackerone.com/en/articles/8457605-retesting) — accessed 2026-10-27; it supplies platform context, not a universal workflow for other programs. Recheck the actual program instructions when platform-specific behavior matters.


For a cross-cutting evidence decision, consult the [family guide](references/decision-playbook.md) only when useful.
