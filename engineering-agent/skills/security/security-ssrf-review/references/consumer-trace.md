# Follow the destination to the connection

## Record the decision at each stage

| Stage | Evidence to resolve | A common invalid inference |
|---|---|---|
| Input | Which URL components are actually caller-controlled? | Every URL-shaped string is fetched |
| Parse/normalize | Which parser output is validated and consumed? | Two URL parsers necessarily agree |
| Resolve | Which A/AAAA answers and proxy path are considered? | An allowed hostname always resolves to an allowed address |
| Connect | Which peer address is actually used? | A separate earlier DNS check pins the later connection |
| Redirect/retry | Is each new destination/connection constrained? | Validating the first URL protects later hops |
| Response | Is data returned, stored, or only a request emitted? | A callback proves credential extraction |

Choose the row supported by the implementation, not all possible URL tricks. Public callback reachability can establish a request primitive while internal reachability remains untested.

## Owned redirect experiment

Use two owned endpoints with unique per-run markers. The product policy permits endpoint P and forbids endpoint Q. First confirm a normal fetch to P produces an application-origin request. Then make P return a redirect to Q and correlate requests at both endpoints with the submitted marker. Preserve request source and time; a browser visiting the callback is not a server fetch. If Q receives nothing but P also receives nothing, the experiment is inconclusive.

No real metadata endpoint or internal service is necessary. An owned denied endpoint tests the policy boundary without collecting credentials. If the actual policy intentionally allows Q, this is not an SSRF boundary violation.

## Repair without breaking TLS

Illustrative state machine:

```text
parse with the consuming client's semantics
apply allowed scheme/host/port policy
resolve using the actual deployment path
validate destinations under that policy
connect only through a supported validated-address mechanism
preserve original reference hostname for SNI/certificate verification
on redirect or relevant retry: repeat the destination decision
```

This is a design invariant, not drop-in DNS-pinning code. A client/proxy that resolves independently requires enforcement at that actual boundary. Do not recommend disabling certificate verification to connect to a numeric IP. Name the required client/egress capability when it is unavailable, and retain that repair gap.
