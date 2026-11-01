# Investigation

## Open first

Exact Next.js/React versions and deployment build, action implementation and references, authentication helper, data-access consumer and an owned two-actor fixture when dynamic verification is appropriate.

## Follow the actual boundary

1. Establish that an action is exported and reachable in the assessed build. Preserve the legitimate request/form or source reference; do not guess action IDs or spray framework endpoints. Framework manifests and action references are routing artifacts, not authorization decisions.
2. Trace every untrusted argument, FormData field, bound value and referenced object into the protected operation. Resolve where identity and tenant are derived. Re-run object/role authorization in the action or an authoritative data-access layer; a page-layout gate and a hidden button do not secure a direct invocation.
3. Inspect closed-over values and bound identifiers as inputs with provenance, not permanent capabilities. A captured permission snapshot can become stale. Encrypted closure transport does not replace checking current membership, object state or one-time-use requirements at execution.
4. For controlled verification, capture one legitimate invocation by an owned actor and vary one policy-relevant field or entitlement. Compare the committed effect or returned owned marker, not only an HTTP status. Use a reversible local mutation or source proof if production state changes are outside scope.
5. Inspect error, redirect and revalidation paths. Confirm that an authorization failure aborts the mutation before partial effects. A successful transport response may carry an application-level error; an exception after a database write is not an effective denial.
6. Review the effective proxy/origin configuration against this installed version. Document built-in origin defenses and custom allowed origins without assuming they implement object authorization. Treat framework-version advisories as a separate, verified applicability question.

## Controls and alternative explanations

- Pair the entitled actor with an owned actor lacking the exact object/action entitlement; hold the action/build constant.
- A reachable action with a proper server-side denial is not an authorization finding. Unused functions or a source-only action name do not establish a live endpoint.
- For stale entitlement, revoke an owned membership in an isolated fixture and invoke the previously rendered action; distinguish policy-defined continued access from a missed recheck.

## Finish or preserve the missing edge

Report the actual missing invocation-time boundary and demonstrated effect. Repair it in the authoritative mutation path, then verify denial, entitled success and absence of partial commits on the repaired build.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://nextjs.org/docs/app/guides/data-security](https://nextjs.org/docs/app/guides/data-security)
- [https://nextjs.org/docs/app/api-reference/directives/use-server](https://nextjs.org/docs/app/api-reference/directives/use-server)
- [https://react.dev/reference/rsc/server-functions](https://react.dev/reference/rsc/server-functions)
