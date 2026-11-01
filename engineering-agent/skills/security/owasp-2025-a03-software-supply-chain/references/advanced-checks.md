# A03:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A03-01 — Advisory applicability

- Trace: Final image/bundle -> resolved dependency graph -> affected feature/config.
- Controlled verification: Use supplied runtime/client evidence and publisher advisory; report invisible backend graph as unknown.
- Discriminator: Version presence is not complete reachability evidence; unsupported software is a separate risk.
- Acceptance: Ship a supported fixed graph; verify the actual final artifact rather than only manifest text.

## A03-02 — Registry and namespace resolution

- Trace: Name/scope -> resolver precedence -> locked source -> installation.
- Controlled verification: Inspect supplied lock/source metadata or explicitly exposed client asset identity.
- Discriminator: Do not publish a conflicting package; source inference from a name is insufficient.
- Acceptance: Intended trusted source is selected reproducibly; private names cannot resolve through unintended sources.

## A03-03 — Untrusted build inputs

- Trace: Trigger/PR context -> checkout revision -> executed script -> secrets/permissions.
- Controlled verification: Use local workflow review and an isolated inert demonstration if needed.
- Discriminator: Read-only isolated builds differ from privileged execution of untrusted contributions.
- Acceptance: Untrusted code never inherits unauthorized publishing credentials or release authority.

## A03-04 — Release artifact identity

- Trace: Approved revision/build -> artifact origin/digest/provenance -> deployment.
- Controlled verification: Compare approved out-of-band identity with supplied artifact bytes.
- Discriminator: An adjacent attacker-supplied checksum does not establish origin.
- Acceptance: Reject unknown/changed artifacts before consumption; reconcile shipped identity with approved release.

## A03-05 — Build tools, actions and images

- Trace: IDE/build plugin/action/container -> version/pin -> lifecycle behavior.
- Controlled verification: Review supplied build configuration; do not run unknown hooks to discover behavior.
- Discriminator: A moving tag alone needs the relevant trust/update policy before severity assignment.
- Acceptance: Required dependencies/tooling have controlled origin, update ownership and proportionate privileges.

## A03-06 — Fix, exception and deployment

- Trace: Advisory -> smallest supported upgrade/mitigation -> lockfile -> rebuilt artifact.
- Controlled verification: Validate delivered component identity and feature tests from supplied evidence.
- Discriminator: A scanner disappearing after dependency removal is not proof of a clean final image.
- Acceptance: Affected path is repaired in the shipped build; temporary exceptions state owner, scope and expiry.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
