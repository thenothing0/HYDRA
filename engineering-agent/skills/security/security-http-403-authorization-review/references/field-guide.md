# HTTP 403 and intermediary authorization bypass assessment — decision procedure

## Establish the boundary

Establish why the request is denied: authentication, operation/object policy, WAF, geography or feature state. Map edge/gateway/origin canonicalization and the authoritative handler, including who can supply forwarded identity/routing headers.

## Smallest decisive verification

Use one concrete mismatch hypothesis at a time and a tiny request matrix: denied actor/baseline, the same actor/one justified variation, and an entitled actor/control. Record canonical handler, protected bytes or committed state; compare bodies and state, not status alone.

## Reject or narrow unsupported conclusions

A 200 login page, soft-denial JSON, public resource, different route or intermediary error is not a bypass. A 403 after committing the operation is still a failure. Never treat a guessed header list or changing User-Agent as evidence of missing authorization.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Normalize once and enforce the required actor/resource/action policy at the trusted execution boundary. Strip/recreate trusted headers at the boundary that owns them. Retest original baseline, the observed variant, entitled use and rejection before side effects.

## Evidence worksheet

scope/policy; actor entitlement matrix; raw and canonical route/method; header provenance; edge/origin response identity; body/state evidence; authorized positive control; request budget; side effects

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
