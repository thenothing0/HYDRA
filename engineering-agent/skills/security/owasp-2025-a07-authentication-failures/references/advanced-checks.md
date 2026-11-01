# A07:2025 — advanced decision checks

Use only controls relevant to the actual application. These are analyst-authored procedures grounded in the linked OWASP category and technical references, not a complete CWE inventory or evidence that each control was executed. Prioritize exposed high-impact boundaries first.

## A07-01 — Recovery recipient and identity

- Trace: Account lookup -> verified destination -> token subject/purpose -> reset.
- Controlled verification: Use two controlled accounts/inbox sinks and track each recovery stage.
- Discriminator: A success page is not evidence of token delivery, reset or account takeover.
- Acceptance: Recipient, subject and purpose remain bound; unauthorized destination gets no recovery authority.

## A07-02 — Token trust contract

- Trace: Allowed algorithm/key source -> signature -> issuer/audience/purpose/time -> caller.
- Controlled verification: Vary one claim/trust property in a local or explicitly controlled token fixture.
- Discriminator: Readable JWT claims and unaccepted malformed tokens are not forgery.
- Acceptance: Tokens outside the application contract reject on the actual protected path.

## A07-03 — Session rotation and revocation

- Trace: Anonymous session -> login/privilege change -> refresh/logout/reset -> server authority.
- Controlled verification: Compare controlled pre/post-transition sessions against the declared policy.
- Discriminator: Stateless bounded lifetime and immediate revocation are different documented models.
- Acceptance: Session behavior matches the chosen policy across refresh and alternate paths.

## A07-04 — MFA and recovery branch consistency

- Trace: Primary login -> factor challenge -> recovery/fallback -> authenticated authority.
- Controlled verification: Check controlled branches and identify whether reset still requires the factor.
- Discriminator: Password reset does not imply full takeover when a second factor remains effective.
- Acceptance: Lower-assurance branches cannot bypass a required factor or bind it to the wrong identity.

## A07-05 — Federation and account linking

- Trace: Redirect/callback -> state/nonce -> provider subject -> local account linkage.
- Controlled verification: Use controlled provider identities and registered callbacks only.
- Discriminator: Similar email display strings do not prove equivalent verified identity.
- Acceptance: Federated response is bound to the intended session/provider/account and valid trust contract.

## A07-06 — Authentication abuse controls

- Trace: Attempt identity/source -> counter key/window -> delay/lockout -> recovery.
- Controlled verification: Inspect configuration or use a small agreed test-account request budget.
- Discriminator: Do not spray credentials; a small timing sample is weak evidence.
- Acceptance: Required throttling resists simple key bypass and avoids unintended real-user lockout.

## Decision handoff

For a candidate, state intended policy, actor/input control, reachable boundary, observed effect, competing explanation and the smallest check that would resolve uncertainty. Keep a rejected hypothesis with its reason in working notes; do not convert it into a finding. A source-only proof and an external observation can support different confidence/impact claims. Cross-reference shared causes instead of counting the same defect twice.

Use [verification.md](verification.md) for evidence collection and [review-rubric.md](review-rubric.md) for delivery. Consult [research.md](research.md) for the primary references relevant to each check.
