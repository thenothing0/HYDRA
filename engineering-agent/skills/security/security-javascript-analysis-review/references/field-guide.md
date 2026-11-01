# JavaScript application and bundle security analysis — decision procedure

## Establish the boundary

Preserve original bundle/hash/build and recover available source-map provenance. Trace entry points, imports, lazy chunks, request builders, data storage and privileged consumers; record runtime browser/Node context and which code actually ships.

## Smallest decisive verification

Use AST-derived calls with original locations as leads. Resolve dynamic values manually or with supported tooling, then tie the call to actor, origin, method, credentials and a protected consumer. Use inert local consumers or owned test accounts for decisive verification.

## Reject or narrow unsupported conclusions

Dead code, test configuration, a public client identifier, an admin-looking route or a published source map alone is not a vulnerability. A source map may aid analysis without exposing a secret. AST extraction is not interprocedural data-flow analysis.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Repair the actual trust/sink boundary; minification, renaming a route or hiding the bundle does not repair server authorization. Retest the affected feature, dynamic/lazy variant and a permitted control on the deployed build.

## Evidence worksheet

bundle/build hash; original location and mapped source provenance; runtime/actor; call arguments and unresolved values; source-to-consumer trace; confirmed effect; benign alternative; tested build

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
