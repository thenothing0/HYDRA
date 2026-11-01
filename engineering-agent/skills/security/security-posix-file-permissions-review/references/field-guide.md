# POSIX privileged file creation and path authority — decision procedure

## Establish the boundary

Trace real/effective identities, supplementary groups, directory ownership/modes, umask and descriptor creation/use. Determine who controls each parent component and whether a pathname check refers to the same object later used.

## Smallest decisive verification

Use an isolated owned temporary tree and inert marker files under ordinary privileges. Compare a permitted operation with a controlled link/parent substitution using supported local APIs; never target system files or perform a real privilege escalation.

## Reject or narrow unsupported conclusions

O_NOFOLLOW typically concerns the final path component; it is not universal parent-path protection. A world-writable directory or setuid bit alone is insufficient without the actual object/authority/consumer path.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Use appropriate descriptor-relative, atomic creation and containment/permission APIs for the platform. Retest intended files, denied replacement/link paths, cleanup and descriptor identity; record what race timing or platform behavior remains untested.

## Evidence worksheet

uid/gid/capability context; parent ownership/modes; open/check/use trace; link semantics; local before/after object identity; platform-specific API; valid creation and cleanup

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
