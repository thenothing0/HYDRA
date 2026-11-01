---
name: security-password-storage-review
description: "Review password verifier format, hashing parameters, salts and migration. Use for offline-verifier risk and verify/rehash behavior; never collect production passwords or run password cracking."
---

# Password verifier storage, migration and resource policy

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. [Runtime contract](references/runtime-contract.md) describes missing-capability fallbacks. No sibling skill or vendor API is required.

Read the [field guide](references/field-guide.md) for this specific trust boundary. Establish the invariant and a legitimate control before choosing verification. A complete source proof can support a finding; label it separately from runtime observation. Do not turn an inventory lead into a confirmed impact.

Required evidence: library/verifier schema; parameter and salt model; secret-management boundaries; legacy migration; verify behavior; local budget; deployment capacity assumptions and valid/invalid controls.

Use [finding-template.md](assets/finding-template.md) for one independent root cause, then [report handoff](references/report-handoff.md) for owner/program routing and formatting. Retest the failing behavior and legitimate control on the changed build before claiming a fix. Scope, missing prerequisites and uncertainty belong in the report.

[Control catalog](assets/control-catalog.json) creates a plan, not a completed assessment. OWASP A04 is a planning lens; select final taxonomy from the actual root cause. [Primary reference](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) accessed 2026-10-27; apply the deployed version/provider/ABI rather than blindly copying current defaults.
