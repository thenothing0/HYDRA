# Investigation

## Open first

Issuer/consumer code, token storage/expiry semantics, email template and redirect settings, declared cross-device behavior, mail-preview behavior and controlled mailboxes/accounts. Source/local review remains possible without a mailbox.

## Follow the actual boundary

1. Trace request -> issuance -> delivered link -> consumption -> resulting session. Record whether the flow silently creates accounts, permits cross-device login, or binds a browser through PKCE/transaction state. None of those product choices is a flaw without an applicable security requirement.
2. Check that the consumer binds the capability to the intended account, purpose, expiry and pending login. Query email/account/tenant values must not replace the identity represented by the issued capability. A token hash used for exchange can itself be a login capability; do not call it non-sensitive merely because it is named hash.
3. Review one-time consumption and session creation as one authoritative transition. Distinguish a token rejected on replay from a second session already created before the rejection. Prefer a deterministic local replay/concurrency fixture to live bursts or repeated email issuance.
4. Evaluate login-CSRF or account-confusion only through an actual session outcome with owned identities. An intentionally portable link is not automatically vulnerable because it works in another browser. Establish whether the victim is unexpectedly signed into an attacker account or a protected action becomes bound to the wrong identity.
5. Follow redirects, fragment/query handling and page subresources on the legitimate link. A real capability exposed to a recipient that should not receive it can matter; replacing it with an arbitrary query marker proves only URL handling. Do not send real login links through external analysis sites or use uncontrolled inboxes.
6. Account for email scanners/prefetch. A passive GET that consumes a capability may cause a reliability or security consequence, depending on the actual session policy. Check the owner's intended confirmation step, token redaction and cache/referrer handling without treating every scanner interaction as account compromise.

## Controls and alternative explanations

- Pair two owned identities and verify the final authenticated identity server-side; a welcome screen or changed URL is insufficient.
- Contrast first use, replay and expired use in a local fixture. A denial without checking whether a session was minted is incomplete.
- Preserve declared browser/cross-device policy. Missing universal device binding is not a finding on its own, and a reset token has a different purpose from a login capability.

## Finish or preserve the missing edge

Report the exact account/purpose/session boundary crossed, supported token lifecycle and observed effect. Retest the legitimate same-device/cross-device path allowed by policy, replay rejection and session invalidation after repair.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://supabase.com/docs/guides/auth/auth-email-passwordless](https://supabase.com/docs/guides/auth/auth-email-passwordless)
- [https://auth0.com/docs/authenticate/passwordless/authentication-methods/email-magic-link](https://auth0.com/docs/authenticate/passwordless/authentication-methods/email-magic-link)
- [https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
