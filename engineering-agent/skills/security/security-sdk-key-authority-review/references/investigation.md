# Investigation

## Open first

A redacted key fingerprint, the attributable configuration and consuming code, provider/key type, documented operations and existing testing scope. Keep full values out of reports, command history and public searches.

## Follow the actual boundary

1. Find the complete consumer, not just a variable named API_KEY. Follow configuration into initialization, headers, URL parameters or an SDK option. Resolve branch selection, environment and origin so the active value is not confused with a fallback or unused setting.
2. Classify the apparent key role from authoritative evidence: project identifier, publishable/client collection token, short-lived user token, query credential or administrative key. Syntax and entropy can select candidates; they cannot establish this classification. Record the exact provider documentation section or owner configuration supporting it.
3. Build separate rows for collection/session creation, reading a caller-owned session, historical report queries, cross-customer data, billing changes and administration. Mark each row `source-use`, `documented-grant`, `observed-grant`, `observed-denial` or `unknown`, with its artifact and principal/resource binding. Do not label untested operations denied.
4. Preserve existing authorization. Normal loading of the in-scope application can reveal the intended integration. If a direct provider operation is in scope, choose a single documented operation on an owned synthetic object with a paired unprivileged control. Do not enumerate real customer identifiers, query other people's reports or turn a bank assessment into an assessment of its vendor account. Missing vendor scope does not prevent source review.
5. Interpret a response at the correct layer. A 200 script load, a created collection session or a public health response does not prove report-read permission. A 403 can be caused by key restrictions, actor policy, network controls or a wrong request shape; without distinguishing evidence it is not proof of invalidity.
6. Check restrictions using owner configuration when available: allowed applications/origins, API allowlists, object/tenant binding, expiry, quota and revocation. A client-distributed key can still have excessive grants; intended publication does not settle that question.

## Controls and alternative explanations

- Compare the active and fallback key branches and trace each to a specific consumer.
- Use an owned test account/object for any authorized operation; an intentionally public asset is a poor control for private report access.
- Record SDK initialization success separately from credential acceptance, data returned and protected effect. A missing SDK on one login page is inconclusive for other lifecycle phases.

## Finish or preserve the missing edge

Deliver the authority table with unknowns intact. Report a key exposure only when an unintended authority or confidentiality consequence is supported. Owner-directed revocation and tightened grants are different repairs; recheck both when relevant.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://developers.google.com/maps/api-security-best-practices](https://developers.google.com/maps/api-security-best-practices)
- [https://firebase.google.com/docs/projects/api-keys](https://firebase.google.com/docs/projects/api-keys)
- [https://docs.stripe.com/keys](https://docs.stripe.com/keys)
