# Finding record

Use one record per root cause; remove instructional text when producing a report.

- ID / title:
- Status: confirmed | suspected | unverified | patched-unverified | fixed | not-reproduced
- Taxonomy: native domain/control and evidence-supported CWE; OWASP web category only when applicable, otherwise unmapped
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

Provide data classification, device/OS/build state, precise location and lifecycle, actor access prerequisites, redacted synthetic marker recovery, retention requirement and unaffected legitimate use.

Discriminator: A plaintext value visible only to the already-authorized app or a rooted/debug device does not by itself establish the claimed exposure. Encryption is not a substitute for access and key policy.

Scope: Do not label lack of certificate pinning or root detection as this storage defect; route separate issues only when their own security boundary is evidenced.

Taxonomy: MASVS-STORAGE-1 and MASVS-STORAGE-2 as applicable. Select exact final IDs only when supported by the root cause.
