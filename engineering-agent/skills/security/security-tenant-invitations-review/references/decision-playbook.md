# Identity proof, credential purpose and lifecycle

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Draw the identity state machine: anonymous, partially authenticated, fully authenticated, recovery, factor replacement and revoked. Record what account, issuer, audience, purpose, recipient and session each token/credential is bound to. A signature is only one part of accepting identity.

Use owned accounts and local mail/factor/IdP fixtures. Compare a valid ceremony with a single wrong binding or stale/replayed operation and observe the final authenticated identity or durable factor/recovery state. Distinguish stubbed cryptographic verification from a real protocol ceremony.

Judge recovery and remembered-device behavior against the declared assurance contract. A designed recovery code, a synced passkey, a zero authenticator counter or an email change shown as pending is not automatically a bypass. Verify which identity can actually act after the transition.

Repair binding and commitment order using supported libraries and an explicit recovery/migration policy. Retest valid login/recovery, denied mismatches, old/new credentials and relevant revocation state. Do not collect real credentials or brute-force production factors.

## Evidence before conclusion

- identity/assurance and recovery policy
- issuer/account/audience/purpose/recipient/session bindings
- challenge/token/factor lifecycle without secret bytes
- final account and durable state, not an intermediate flag
- valid, stale and mismatched-ceremony controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
