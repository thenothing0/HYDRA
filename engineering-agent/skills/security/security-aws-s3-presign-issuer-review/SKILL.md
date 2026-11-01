---
name: security-aws-s3-presign-issuer-review
description: "Review S3 SigV4 capability method/key/version, signed headers and temporary-signer lifetime, including PUT/POST distinctions; generic bucket publication belongs in S3 policy review."
---

# S3 SigV4 issued capabilities: signed fields, signer lifetime and object version

Start from: Signer endpoint/code, signer principal, bucket/key/version selection, expiration and owned objects.

Read [the investigation](references/investigation.md) to select the implementation branch, source trace, discriminating experiment and repair oracle. Use source review, an owned fixture or already authorized verification according to the evidence actually available.

Record the actor/action/resource rule, build/configuration and authoritative consumer result in [the evidence worksheet](assets/evidence-worksheet.md). Keep source proof, local observations, deployment observations and unresolved edges separate. An exposed credential does not extend authority to another service.

[The structured contract](assets/review-contract.json) and [planning control](assets/control-catalog.json) describe unexecuted work, not findings. Draft one report per supported root cause; no default severity or external submission is implied. This folder has no required agent API; missing host capabilities remain explicit.
