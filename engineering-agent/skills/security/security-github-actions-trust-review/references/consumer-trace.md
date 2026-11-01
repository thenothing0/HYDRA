# Trace the bytes consumed with privilege

## Build a provenance table

| Edge | Record from the actual workflow |
|---|---|
| Event to context | Trigger, actor/repository/ref and trust assumption |
| Context to checkout | Exact repository/ref/SHA chosen, including reusable actions |
| Untrusted field to shell | Whether expression text becomes script syntax or is passed as data |
| Job to authority | Token permissions, secrets, environment gate and runner state |
| Artifact to release | Producer run/event/ref, immutable bytes/digest and consumer verification |

For each edge, name which identity can change the consumed bytes. A safe event name does not establish a safe checkout, and a privileged trigger alone does not establish a vulnerability.

## Review one concrete mismatch

Suppose a privileged workflow runs after an untrusted contribution workflow. The release job selects an artifact by display name. Determine whether it binds that artifact to the approved repository, event/ref, run identity and exact digest, or whether an untrusted producer can supply different bytes with the same name. Inspect verification before extraction/execution/promotion.

Do not run unknown contributor code with a real privileged token to prove the path. A local artifact/consumer fixture or complete workflow source trace can establish the binding problem. Keep unavailable reusable workflows or runner configuration as specific missing edges.

For direct script interpolation, distinguish expression insertion into a generated command from passing a value through a supported data/environment boundary. The consumed tool may still interpret dangerous options; preserving a shell argument boundary is not universal authorization.

## Repair acceptance

Separate untrusted execution from privilege and bind promoted bytes to an approved producer/context. Inspect reusable workflow permissions and runner persistence only where they affect the evidenced path. Retest normal contribution/release and the exact untrusted-to-privileged transition. Do not recommend a wholesale CI rewrite based only on a trigger keyword or an advisory with no reachable callsite.
