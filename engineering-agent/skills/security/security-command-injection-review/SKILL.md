---
name: security-command-injection-review
description: "Review process execution and argument/option trust. Use for OS command injection and unsafe process options; prefer inert local stubs over shell side effects."
---

# OS command and argument injection

Read [the investigative procedure](references/investigation.md) first: it selects the decisive artifacts, experiment, disproof and repair acceptance for this technique. Start with the user's actual feature and requested mode; do not run a fixed payload list.

Use the existing technique guidance below for implementation-specific paths. Keep inventory, complete source proof and observed runtime effect distinct. When a decisive edge is missing, follow the procedure's specific next-artifact branch rather than guessing.

## Investigation

1. Trace executable selection, shell invocation, string construction, argument boundaries, working directory, environment and downstream option parsing. Identify exactly which element the caller controls.

2. Use a harmless stub process or instrumentation to observe received argv and intended operation. Prove altered instruction/option semantics without running destructive commands or opening a remote shell.

3. Inspect wrappers, platform-specific paths, background jobs and fallback executors. Fixed executables with shell-free arrays still need safe options and constrained file/URL arguments.

4. Use supported APIs that avoid unnecessary interpreters; fix executable/option authority and least-privilege operation. Retest legitimate paths/spaces, rejected option changes and the original instruction boundary.

## Evidence and discrimination

A suspicious character or subprocess occurrence is not command execution proof. Showing a single quoted argument does not establish that the invoked tool interprets it safely.

Include entry point, process API, exact argument vector from a stub, executable/option policy, observed effect and legitimate operation control.


## Reporting and closure

Use [finding-template.md](assets/finding-template.md) for one independent issue per report. Preserve expected/observed behavior, prerequisites, exact evidence, contextual severity and test limits. Separate plausible escalation from demonstrated consequence. [Report handoff](references/report-handoff.md) covers manual routing when the optional reporting skills are absent.

If available, security-finding-report writes each issue separately, security-disclosure-routing verifies the owner/policy/channel, and security-platform-report adapts the draft. Do not infer a destination or transmission authorization from report preparation. Retest the original failure, permitted control and relevant state effects on the changed build before closing a fix.

The initial classification lens is OWASP A05:2025 and CWE-78; choose the final mapping from the actual root cause, not the technology name. [Control catalog](assets/control-catalog.json) is planning guidance, not an executed assessment or exhaustive certification.

## Reference

[Primary technical reference](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) — retrieved 2026-10-27. Consult the sections applicable to the actual library/provider/deployment and current primary documentation for version-sensitive decisions. No real target was assessed while authoring this workflow.
