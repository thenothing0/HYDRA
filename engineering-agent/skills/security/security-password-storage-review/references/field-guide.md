# Password verifier storage, migration and resource policy — decision procedure

## Establish the boundary

Trace password enrollment, verify, reset and migration through the actual library and stored verifier version/parameters. Distinguish reversible encryption or general hashes from a supported password KDF, and record salt/pepper and Unicode/length semantics.

## Smallest decisive verification

Use nonsecret fixture passwords and locally bounded parameter measurements. Compare valid/invalid verification, migrated legacy records and the application input-length/resource policy without online spraying or collecting real password hashes.

## Reject or narrow unsupported conclusions

A modern algorithm name alone does not establish suitable parameters or correct integration. A pepper does not replace a salt; a stronger new hash does not automatically migrate dormant users or secure old backups.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Use current supported guidance and environment-appropriate parameters, with safe versioned rehash and recovery handling. Retest valid legacy/new accounts, invalid input, length/encoding behavior and bounded resource use; avoid hardcoded universal tuning values.

## Evidence worksheet

library/verifier schema; parameter and salt model; secret-management boundaries; legacy migration; verify behavior; local budget; deployment capacity assumptions and valid/invalid controls

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
