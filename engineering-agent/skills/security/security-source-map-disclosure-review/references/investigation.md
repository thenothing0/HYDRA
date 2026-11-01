# Investigation

## Open first

The exact map and generated bundle, their acquisition URLs/times and hashes, deployment/build identifiers, and the owner's intended publication policy. Repository access is useful but not required for an initial exposure review.

## Follow the actual boundary

1. Establish the distribution path. Distinguish a response body that is a v3 map from an HTML fallback returning 200. Record response metadata and whether authentication was needed. Preserve original bytes; a file extension is not evidence of content.
2. Correlate the generated bundle, actual page reference and map. A `file` field or familiar source name is a claim inside the artifact, not proof of build identity. Compare attributable copies and a concrete generated consumer. Do not silently combine source from different deployments.
3. Inventory `sources`, available `sourcesContent`, indexed sections and repeated variants. Read source labels as data. Never create a file using `sourceRoot` or a source label; never follow section URLs or fetch mapped paths automatically. The optional inspector reports hashes and missing content, not validated source mappings.
4. Classify disclosed content: ordinary shipped client logic; additional comments/internal paths; a server-only module or credential; or a fixture/dependency example. For a secret-looking value, trace the issuer, consumer and intended distribution using redacted fingerprints. A public SDK identifier is a separate authority question.
5. Establish incremental impact. A route already present in minified code is not newly protected data. A genuinely private server credential embedded only in the map can be a disclosure even without logging into its service. Source-only proof needs an actual sensitive value and a defensible confidentiality requirement, not a generic claim that reverse engineering became easier.
6. Separate the exposure root cause from a vulnerability discovered with the source. Missing map access controls and an independently reachable XSS have different effects; do not count the same XSS twice or infer severity from source-file counts.

## Controls and alternative explanations

- Compare a permitted public client module to the suspected protected module; explain why their intended audiences differ.
- Treat missing `sourcesContent`, an unmatched generated build, a map containing public open-source dependencies, and a test/example key as explicit alternative explanations.
- If the file is authenticated, test only the intended actor boundary with owned identities. Possession in an authorized debugging console is not public exposure.

## Finish or preserve the missing edge

Stop at an exposure observation when the only demonstrated content is ordinary browser code. For remediation, verify that the affected deployment no longer distributes the protected material through maps, bundles, caches or artifact history. Deleting the map does not revoke a leaked credential.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage)
- [https://tc39.es/ecma426/](https://tc39.es/ecma426/)
