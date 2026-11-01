---
name: security-posix-file-permissions-review
description: "Review POSIX privileged file operations and directory ownership. Use for unsafe temporary files, link/parent path authority and descriptor-to-file mismatches, distinct from lexical traversal alone."
---

# POSIX privileged file creation and path authority

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

Use the requested source-review, authorized verification or remediation mode. [Runtime contract](references/runtime-contract.md) describes missing-capability fallbacks. No sibling skill or vendor API is required.

Read the [field guide](references/field-guide.md) for this specific trust boundary. Establish the invariant and a legitimate control before choosing verification. A complete source proof can support a finding; label it separately from runtime observation. Do not turn an inventory lead into a confirmed impact.

Required evidence: uid/gid/capability context; parent ownership/modes; open/check/use trace; link semantics; local before/after object identity; platform-specific API; valid creation and cleanup.

Use [finding-template.md](assets/finding-template.md) for one independent root cause, then [report handoff](references/report-handoff.md) for owner/program routing and formatting. Retest the failing behavior and legitimate control on the changed build before claiming a fix. Scope, missing prerequisites and uncertainty belong in the report.

[Control catalog](assets/control-catalog.json) creates a plan, not a completed assessment. OWASP A01 is a planning lens; select final taxonomy from the actual root cause. [Primary reference](https://man7.org/linux/man-pages/man2/open.2.html) accessed 2026-10-27; apply the deployed version/provider/ABI rather than blindly copying current defaults.
