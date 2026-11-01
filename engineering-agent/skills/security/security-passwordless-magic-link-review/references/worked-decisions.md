# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Intentional cross-device use
An owned user's link signs that same user in on another browser, as documented. There is no wrong-account session or violated transaction requirement. Portability alone is not a bypass.

### Wrong-account binding
In a local fixture, a link issued to owned account A accepts a caller-supplied account B at consumption and creates a B session. Preserve issuance identity, consumption binding and server-confirmed session identity. This is an authentication binding failure.

### Synthetic query is insufficient
A random `token=CANARY` reaches an analytics endpoint on an error page. There is no legitimate issuer/consumer proof for the value. Keep it as URL forwarding evidence, not a demonstrated magic-link credential leak.
