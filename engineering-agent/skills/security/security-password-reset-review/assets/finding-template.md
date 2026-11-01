# Finding record

Use one record per root cause; remove instructional text when producing a report.

- ID / title:
- Status: confirmed | suspected | unverified | patched-unverified | fixed | not-reproduced
- Category: OWASP A__:2025; secondary categories only when helpful
- CWE: evidence-supported identifier, or unmapped
- Target: repository/commit, artifact/build, environment, path/route and line
- Scope: identities, synthetic records, authorized actions and exclusions
- Security requirement / expected behavior:
- Preconditions: role, feature, configuration, network access and version
- Observed behavior:
- Evidence: source trace or request/response identifiers, timestamps, commands, output paths; redact secrets
- Reproduction: minimal steps and paired permitted/denied controls
- Impact: actual demonstrated boundary and separately labeled plausible consequences
- Severity / rationale: exposure, prerequisites, asset sensitivity, blast radius, compensating controls; CVSS vector only if calculated
- Confidence and limitations:
- Root cause and other affected entry points:
- Remediation: code/config/design location, migration needs, owner and rollback concerns
- Verification: pre-fix result, post-fix result, valid behavior, side-effect checks, build tested
- Coverage: performed / not performed / not applicable, with reason
- References: original publisher, URL, publication/update date, relevance; historical case mapping labeled as analysis

Closure requires the original failure to be prevented on the tested build and legitimate controls to pass. A supplied patch without a retest is patched-unverified. An HTTP status alone is insufficient when state may already have changed.

## Evidence specific to this workflow

Provide controlled account/inbox roles, token lifecycle trace, stage-specific observed consequence, replay/expiry controls and the remaining MFA/session limits.

Discriminator: A generic success response does not prove delivery or takeover. Password reset is not full account takeover if an effective required factor still blocks login.
