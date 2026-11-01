# Investigation

## Open first

Owned project/buckets, intended public/private model, effective storage.objects policies and helpers, SDK/API versions, server signer code and two owned users/tenants with synthetic objects.

## Follow the actual boundary

1. Identify bucket privacy and the exact operation/endpoint. Intentional public download is different from listing, overwriting or deletion. Do not treat every public object URL as a misconfiguration or assume one SELECT outcome describes every Storage action.
2. Trace the client identity and credentials to the effective Storage request. Separate an anonymous/publishable project key, an authenticated user token and a server service credential. Privileged server clients can bypass ordinary client RLS; a successful admin control does not show that a user can do the same.
3. Read the applicable storage.objects policies, permissive combinations and version-specific helpers. Examine bucket binding, owner_id, folder prefixes and any client-writable metadata used as authority. A plausible path prefix is not inherently tied to the JWT subject or current tenant membership.
4. Exercise only synthetic objects in owned buckets/users. For each relevant operation compare entitled success and restricted failure. For upsert/replace, inspect both creation and modification requirements; for copy/move, examine source and destination authorization separately. Preserve stored state and cleanup receipts, not only SDK error text.
5. Inspect signed-link issuance at the application boundary. A deliberately transferable signed URL is a capability; the central question is whether the requester was allowed to obtain it for that object and whether its lifetime/scope matches policy. Possession-based access by design is not automatically an RLS bypass.
6. Review server wrappers that use service credentials: requester-to-object binding, tenant checks and resource selection must happen before privileged calls. Source-only proof can identify a complete missing check, but do not claim a dynamic cross-user read from an endpoint string alone.

## Controls and alternative explanations

- Use a public test object as a publicity control and a separate private synthetic object for access controls.
- Keep the Storage endpoint, actor role and bucket configuration in each result; testing only with a service credential hides client policy defects.
- Compare object existence from an entitled actor so a 404 is not mistaken for an effective denial.

## Finish or preserve the missing edge

Report the precise operation, object and actor boundary. Repair bucket/policy/wrapper authority as appropriate, then retest entitled use and denial across source and destination paths. Avoid deleting original objects or changing a live bucket's privacy during discovery.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://supabase.com/docs/guides/storage/security/access-control](https://supabase.com/docs/guides/storage/security/access-control)
- [https://supabase.com/docs/guides/storage/buckets/fundamentals](https://supabase.com/docs/guides/storage/buckets/fundamentals)
- [https://supabase.com/docs/guides/storage/security/ownership](https://supabase.com/docs/guides/storage/security/ownership)
