# Native bounds, ownership and object lifetime — decision procedure

## Establish the boundary

Trace untrusted lengths/indexes and object ownership through allocations, copies, callbacks, error cleanup and concurrent/lazy consumers. Record compiler/ABI/build flags and the lifetime or bounds invariant at the actual access.

## Smallest decisive verification

Prefer a complete source trace or a tiny reviewed harness using fake data and supported instrumentation. Preserve the original artifact and stack/location; cap input and runtime and stop at the first invalid access, without exploitation or address-layout bypass work.

## Reject or narrow unsupported conclusions

A crash is not automatically corruption and a sanitizer-free run does not prove absence. Instrumentation changes behavior; a defect visible only in a mock must not be described as a deployed remote exploit.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Repair ownership/bounds at the earliest authoritative point and retest the original path, valid boundary values and cleanup/error paths under the relevant configuration. Hardened flags complement, rather than substitute for, the root-cause fix.

## Evidence worksheet

entry/reachability; concrete type/size/lifetime; allocation/free/access sites; build/ABI; sanitizer/source evidence; harness divergence; valid/error controls; unverified exploit consequences

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
