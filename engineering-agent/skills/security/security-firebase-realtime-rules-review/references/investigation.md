# Investigation

## Open first

Actual RTDB rules, data shape, client auth/custom-claim context, intended path policy and emulator project configuration. Use a synthetic data tree and rules emulator when production writes are outside scope.

## Follow the actual boundary

1. Confirm the product is Realtime Database and capture the deployed rules revision. Do not apply Firestore match semantics. Distinguish client rules enforcement from privileged Admin/server access, and distinguish App Check attestation from user/object authorization.
2. Evaluate .read and .write grants from the requested path through its ancestors. A shallow allow cannot be canceled by a deeper deny. A root read returning the whole tree is a different operation from a permitted child read; rules are not a post-query row filter.
3. Trace auth.uid, custom claims and any membership/owner field into the grant. Determine who can write each authority field. Use the effective post-write state as well as prior data for updates; an attacker-controlled owner or role must not authorize its own replacement.
4. Review .validate independently of access grants. Identify required fields/types, additional fields and deletion behavior. Validation rules are not read/write authorization, do not inherit like grants, and are not applied to deleted data in the same way as non-null writes. Put deletion-specific authority in the appropriate write policy.
5. In an emulator or owned fixture, compare unauthenticated, owner A and owned non-owner B at an exact known path. Include one relevant multi-location update or deletion when the suspected defect depends on it; inspect the resulting synthetic tree. Avoid production tree enumeration to look for victims.
6. When authorization depends on query shape, reproduce the legitimate order/filter/limit and a specific policy-relevant variation. Index configuration affects query execution, not the identity boundary. Preserve the actual error and requested path rather than calling every failed query denied by a correct policy.

## Controls and alternative explanations

- Verify owner A can access the synthetic record and B cannot under the repaired policy; include an anonymous control only where relevant.
- Keep an Admin-context operation as setup evidence, not proof of a client bypass.
- For a shallow grant hypothesis, show the exact parent grant and child request. A deeper false rule does not undo an already applicable true grant.

## Finish or preserve the missing edge

Report the effective grant or missing post-write invariant with the actual client context. Repair the rules and rerun the relevant emulator/owned-path cases, including allowed writes, forbidden cross-user writes and deletion semantics. An emulator result must not be represented as a deployed production exploit.

When an indispensable artifact is absent, name that exact artifact and what it would distinguish. Continue independent useful review within the existing scope; do not substitute guesses or repeated inconclusive requests. Report a bounded result rather than claiming the whole application is secure.

## Primary references

Reference links checked during authoring on 2026-10-29. Verify version-sensitive behavior against the assessed version; these references do not represent a target assessment.

- [https://firebase.google.com/docs/database/security](https://firebase.google.com/docs/database/security)
- [https://firebase.google.com/docs/database/security/core-syntax](https://firebase.google.com/docs/database/security/core-syntax)
- [https://firebase.google.com/docs/database/security/rules-conditions](https://firebase.google.com/docs/database/security/rules-conditions)
- [https://firebase.google.com/docs/rules/unit-tests](https://firebase.google.com/docs/rules/unit-tests)
