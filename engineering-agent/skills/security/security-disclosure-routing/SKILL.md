---
name: security-disclosure-routing
description: "Find and verify the responsible vulnerability disclosure channel for a specific affected asset and issue. Use official owner policy, security.txt pointers and current program scope; does not submit or select by bounty size."
---

# Find the correct disclosure destination

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Resolve where this specific finding belongs before choosing its report profile. Read [routing-procedure.md](references/routing-procedure.md); use [route-input.json](assets/route-input.json) to record the decision. A text record cannot prove ownership by itself. [Runtime capabilities](references/runtime-contract.md) determine which checks can be executed.

1. Establish the affected product/service and responsible owner using the target context and official sources. Separate deployer, software vendor, hosting provider/CDN and third-party integration. If ownership or the actual affected asset is missing, continue reviewing supplied material and ask only for the missing decision that blocks routing.
2. Inspect the owner’s official security/VDP page and published program link. Fetch the exact host’s /.well-known/security.txt as disclosure information when useful, check freshness/provenance and follow its Policy/Contact pointers carefully. Do not infer testing authorization, parent/subdomain coverage or bounty eligibility from security.txt.
3. Open the current official program brief. Match the exact asset/product/version and finding type, exclusions, program active state, invitation/account access and language/template requirements. Search directories can identify candidates but cannot establish the final route.
4. Compare candidate channels with source URLs and check times. Prefer the owner-designated channel; do not send to several platforms to hedge uncertainty. Preserve conflicting/outdated policies as blockers. If private information is inaccessible, request the relevant program brief or access evidence instead of inventing it.
5. Record the chosen channel and scope rationale per finding, or an unresolved/paused/out-of-scope/needs-access result. Recheck policies immediately before an authorized submission. Do not guarantee reward, eligibility or nonduplicate status from a public search.

The offline script can inspect a saved security.txt file or validate routing assertions/hashes; it does not browse, verify ownership semantically, register accounts, send email or submit. Use existing web capabilities for source discovery. Preparation does not authorize transmission.



For a cross-cutting evidence decision, consult the [family guide](references/decision-playbook.md) only when useful.
