# Investigation

## Open first

The browser version/profile, storage mechanism, top-level and frame origins/sites, ancestor chain, sandbox flags and any recorded storage-access grants. Use synthetic markers rather than real session tokens.

## Follow the actual boundary

1. Write the context matrix before testing: top-level A; A embedded under B; A under C if necessary; and the same-context A positive control. Origins include scheme/host/port; schemeful sites are a different concept. Record ancestor chains and the actual tested API (localStorage, IndexedDB, cookies, CacheStorage or a communication channel).
2. Seed a fresh synthetic marker while A is genuinely top-level, using the ordinary application path or a clearly labeled owned fixture. Read it back there. Do not prepopulate A while it is already embedded under B and describe that value as the user's first-party session.
3. In the same browser context/profile, navigate to B and let the embedded A attempt the relevant read. Record a matching value, a different/empty partition, a blocked read or an exception. Cross-origin parent access is a separate same-origin-policy question; automation's ability to evaluate inside a frame is not attacker capability.
4. Return to top-level A and re-read the marker. This distinguishes isolation from a failed write, eviction, profile replacement or cleanup. If testing Storage Access API, preserve the actual user activation/grant flow and the precise storage type granted; do not assume all APIs become unpartitioned.
5. Inspect the effective browser command line and profile, including automation defaults rather than only the flags the test author wrote. Some Playwright configurations add `ThirdPartyStoragePartitioning` to `--disable-features`; restore the intended browser behavior and record the change before drawing a partitioning conclusion. Keep origin security intact. A run with disabled partitioning is a labeled local diagnostic, not evidence about ordinary victims. Different browser engines, settings, prior grants or embedded-site heuristics require separately recorded outcomes.
6. Connect visibility to impact only through a reachable attacker operation. Even shared synthetic storage does not prove a real user is authenticated there, a token remains valid, an attacker can exfiltrate it, or a protected backend accepts it. Keep these additional edges explicit.

## Controls and alternative explanations

- Positive controls: top-level write/read before and after the cross-site observation, same browser context and matching marker fingerprint.
- Negative alternatives: blocked storage, missing fixture initialization, a different scheme/port, sandbox opaque origin or a new browser context.
- Record HttpOnly/SameSite/Partitioned cookie properties separately from JavaScript storage. Do not substitute a cookie result for a localStorage claim.

## Finish or preserve the missing edge

Report the mechanism and contexts observed, not a universal statement about all browsers. A missing account or legitimate token context leaves authentication impact unverified. Recheck the exact context matrix after a repair; anti-framing and storage isolation address different boundaries.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://privacysandbox.google.com/cookies/storage-partitioning](https://privacysandbox.google.com/cookies/storage-partitioning)
- [https://developer.mozilla.org/en-US/docs/Web/API/Storage_Access_API](https://developer.mozilla.org/en-US/docs/Web/API/Storage_Access_API)
- [https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
