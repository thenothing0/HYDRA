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

Provide producer/consumer workflow revisions, artifact identifier/digest, attacker-controlled selector, verification policy and timing, substituted inert content result and valid-release control.

Discriminator: A valid signature or attestation alone does not authorize the producer for this deployment. Missing one particular attestation feature is not a defect when equivalent trust enforcement is evidenced.

Scope: Use the chosen provider's current attestation/identity model; do not label a metadata-only fixture as a cryptographically verified attestation test.

Taxonomy: Artifact provenance verification; provider identity and consumer policy are distinct. Select exact final IDs only when supported by the root cause.
