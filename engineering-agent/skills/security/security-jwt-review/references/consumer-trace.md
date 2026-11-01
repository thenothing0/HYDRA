# Keep token provenance and token purpose separate

## Reconstruct the verifier-to-account path

Record who issues the token, which trusted keys may validate it, which token class the operation accepts and how the verified subject becomes a local principal. Token header fields are input to key selection, not independent authority to choose a new issuer or remote trust anchor.

Illustrative decision sequence; use the actual library/provider contract:

```text
select the operation's expected issuer/audience/purpose policy
choose keys only from that policy's trusted source
verify allowed signature/algorithm using supported library APIs
validate required claims and transaction/lifetime context
map verified subject within the intended tenant/account namespace
authorize the requested operation/resource
```

A valid signature does not authorize every use of a token issued by the same signer. An ID token, access token and reset token can require distinct validation/consumption rules. Do not impose arbitrary mandatory claim names if equivalent purpose binding is established by the real protocol and consumer.

## Local discrimination matrix

Use nonsecret owned signing keys and synthetic claims. Compare intended valid token, invalid signature, correctly signed wrong-audience/resource token and correctly signed wrong-purpose token. Observe which validation gate rejects each and whether a rejected token reaches the account consumer. A mock verifier can illustrate gate logic but does not prove a production service accepts it.

Also inspect stable subject/account mapping: the same displayed email across identity providers does not necessarily identify the same proven principal. If the root cause is account linking rather than JWT verification, name that boundary accurately.

Retest intended login/API use, the originally accepted wrong context and legitimate key rotation. If only decoded claims are available, the next artifact is verifier configuration/consumer code, not a larger set of mutated tokens. Do not test exposed real tokens against external services.
