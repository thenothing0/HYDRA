# Investigation

## Open first

Exact React/framework versions, server-to-client component boundary, data-access code and serializer/DTO, plus attributable HTML/RSC responses from owned actors or a synthetic local application.

## Follow the actual boundary

1. Map server-only modules, server rendering and client component boundaries. Server execution is not a confidentiality guarantee: values passed into a client boundary may be serialized. Conversely, a secret used only in a server-side calculation is not disclosed merely because that module imports it.
2. Follow the selected record into the actual props, returned structures, error objects and streaming branches. Prefer an explicit allowed-field DTO. A TypeScript type annotation does not remove runtime properties; inspect what is actually constructed and serialized.
3. Inspect browser-received initial HTML and the actual RSC/Flight or navigation payload for the relevant owned marker. Do not execute downloaded protocol content or infer a leak from a string appearing only in server logs or a local debugger. Preserve response provenance and the path to the client boundary.
4. For user/tenant context, use two owned identities with distinct synthetic records. Compare initial and subsequent navigation under the same deployment. Verify request-specific auth derivation and any caching/coalescing that can reuse another actor's data. Do not broadly poison shared production caches to test a local hypothesis.
5. Distinguish excessive fields on an authorized object from an unauthorized object or cache leak; report the actual root cause separately. A valid protocol response and the absence of an on-screen field prove neither a disclosure nor its absence.
6. Review server-only import guards and available taint mechanisms for this version as defense in depth. Neither substitutes for authorization and deliberate projection of public fields. Do not assume an experimental taint API is universally enabled.

## Controls and alternative explanations

- Pass a synthetic public field and a synthetic protected field through the same feature; record which are actually emitted.
- Show that the observing actor lacks the protected-field or object entitlement. If the property is intentionally public, serialization is expected.
- Repeat a clean request after any local cache experiment; a retained browser response is not proof of shared server caching.

## Finish or preserve the missing edge

Report the exact protected values/fields delivered to the actor, with redacted wire evidence. Repair the server data-access/projection/cache boundary and retest both confidentiality and legitimate rendering.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://nextjs.org/docs/app/guides/data-security](https://nextjs.org/docs/app/guides/data-security)
- [https://react.dev/reference/rsc/server-components](https://react.dev/reference/rsc/server-components)
- [https://react.dev/reference/rsc/use-client](https://react.dev/reference/rsc/use-client)
