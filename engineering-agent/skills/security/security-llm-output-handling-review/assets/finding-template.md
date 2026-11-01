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

Include producer influence, exact generated-field-to-sink path, consumer context, stub versus live-model evidence, inert downstream effect and valid-output control.

Discriminator: An alarming string in a chat answer is not code execution. Schema-valid JSON does not establish that fields are safe for a shell, SQL expression or HTML context.

Scope: Route a confirmed SQL/XSS/command defect to the corresponding technique report and link the model ingress; avoid duplicate reports for the same root cause.

Taxonomy: OWASP LLM05:2025; classify the actual downstream injection boundary separately. Select exact final IDs only when supported by the root cause.
