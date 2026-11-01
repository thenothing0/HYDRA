# 403 assessment: demonstrate a violated authority rule

## Identify the denial owner

Start from a concrete authorized asset/action and an explicit policy: who should access which object, function or field? Reproduce the baseline with a controlled low-privilege actor and preserve a successful entitled-actor control. Establish whether the 403 comes from login/session state, application policy, an edge security rule, geography, an unavailable feature or an intermediary. A browser's displayed error and the origin handler can differ.

Choose a meaningful oracle: protected fixture bytes, a controlled state change, an audit record tied to the real handler, or a complete source proof. Response size/status similarity is supporting metadata, not the oracle. Avoid destructive/financial operations when an inert synthetic record or read-only fixture can demonstrate the same authority.

## Derive one mismatch hypothesis

| Boundary | Review before choosing a variation | Decisive observation |
|---|---|---|
| Path parsing | Edge versus application decode/normalize order, route matching, prefix guards and dispatch | Same protected handler is reached with the same unauthorized actor |
| Method dispatch | Registered methods, override middleware and per-method policy | A protected action occurs outside the actor's method/function authority |
| Forwarded identity/routing | Which hop strips/sets each header, trusted peer identity and direct-origin constraints | A client-controlled value is treated as trusted authority at the consumer |
| Alternate representation/route | Versions, format suffixes, exports and shared controllers | The same protected object/action is exposed through an evidenced unguarded path |
| Cache/intermediary | Response source, cache identity and session/authorization keying | Private controlled content is reused for a prohibited actor, rather than a public cached page |

These are investigation classes, not a universal mutation list. Pick the minimum variation justified by source/configuration or actual protocol behavior. Preserve the owner's rate/concurrency/method/data rules, exact asset boundary and existing authorization. Do not mass-spray path/header wordlists, redirect into unapproved hosts, or broaden discovery because a response changed.

For source review, locate the route normalizer, proxy trust configuration, middleware order and operation gate; compare the representation checked with the one used. For a live authorized check, record raw request bytes, actual actor/session, canonical handler identity where available, body/state oracle and one changed dimension. For remediation, enforce normalized actor/resource/action authority at execution and restore required entitled behavior.

## Differential evidence matrix

| Trial | Actor | Input | Required evidence |
|---|---|---|---|
| Denied baseline | Same low-privilege fixture identity | Original protected action | Denial and absence of prohibited effect |
| Candidate variation | Same identity | One justified change | Same protected resource/action plus actual disclosure/commit or source proof |
| Permitted control | Entitled fixture identity | Original action | Feature actually works and oracle can detect it |
| Repaired variant | Same low-privilege identity | Observed variant on changed build | Denial before protected effect, with valid control preserved |

Do not replace the low-privilege identity, target object or build mid-comparison without recording a new prerequisite. Cookies, tokens and intermediary session caches can silently change the actor. A soft denial can be 200; a forbidden action can commit and then return 403. Inspect state after an error when the action can have effects.

## Classification and report

* 200 public content, a login page, an SPA shell or error JSON: not evidence of protected access.
* A different public handler reached by a modified path: not a bypass of the original protected handler.
* Authenticated administrative use: positive control, not an unauthorized exploit.
* Edge/WAF rule evasion: state that narrower behavior and the program's eligibility; it is not automatically application privilege bypass.
* A canonicalization or trusted-header flaw reaching an unauthorized operation: report the actual authorization root cause, intermediary preconditions and observed effect. Similar manifestations sharing that cause belong together.

No evidence of origin reachability or actor policy means the alleged bypass stays unverified. Severity follows actual protected impact and prerequisites. The report should include the baseline/variant/control, normalized consumer, header provenance if relevant, exact build and rejection-before-commit retest. Do not submit a status-code screenshot as a complete PoC.

## Local laboratory

`python scripts/verify_lab.py --record NEW.json` uses only 127.0.0.1 and synthetic actors, headers, records and a credit counter. It makes real local HTTP requests but models edge and origin decisions inside one Python handler. It demonstrates normalization and header-trust bugs, repaired rejection before commitment, entitled use, public success and soft-denial controls. It is not an nginx/Envoy/browser/cloud/WAF implementation test and is not an independent agent evaluation. The intentionally vulnerable fixture is for local training only; it accepts no remote target argument.

## Additional interpretation boundary

The X-Lab-Actor field is a test-harness identity stub, not an authentication implementation. The fixture evaluates decisions for its declared actors; it does not establish real session/token verification.
