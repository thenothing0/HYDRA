# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Expected public retrieval
A bucket intentionally serves marketing images publicly. Anonymous download succeeds, but listing and mutation remain restricted. The retrieval is expected; do not convert it into a private-storage finding.

### Confused signer
A backend uses a service credential and accepts any object path from a logged-in caller before signing a private URL. In an owned fixture, tenant A obtains tenant B's synthetic object capability. Report the missing signer authorization, not a failure of the signed token's cryptography.

### Move boundary
An owned user can read their source object but cannot write into another tenant's destination prefix. A failed destination write means no cross-tenant move was established, even if the source read is allowed.
