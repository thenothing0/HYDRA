# Reconstruct the failure before declaring a fix

An export originally disclosed B's marker to A. On the changed build, a 403 is useful only if no prohibited job/result was produced. Check the queue or durable state, then verify A can still export A's document and B can still read B's. Feature failure, an expired A session or a deleted B fixture makes non-reproduction inconclusive.

| Observation | Supported retest conclusion |
|---|---|
| Original attack denied before effect; entitled control passes on identified changed build | Fixed for this tested path/build |
| 403 returned after the forbidden result was committed | Still reproducible; include state evidence |
| No access to worker/result state and no complete source proof | Missing decisive check; no closure claim |
| All requests fail because test identity expired | Blocked/inconclusive, not fixed |
| Patch inspected but no relevant execution or complete acceptance proof | Patched-unverified |

Retest the originally affected alternate path only where it belongs to the supplied finding/scope. Save old/new build identity and evidence references. A narrower repair can break a proposed chain while leaving independent findings open. The local result does not change a platform report's status or authorize a new submission.
