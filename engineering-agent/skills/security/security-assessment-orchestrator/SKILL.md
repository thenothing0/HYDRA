---
name: security-assessment-orchestrator
description: "Plan and coordinate a multi-domain security review from actual assets and trust boundaries. Use for assessment intake, selecting relevant skills, prioritizing decisive checks and honest coverage; does not run every skill or spawn agents automatically."
---

# Assessment scope, trust-boundary routing and completion ledger

Read the [operating example and decision branches](references/operating-example.md) before choosing the work/output path. It covers a concrete ambiguous case, evidence needed and the narrower result when a decisive edge is missing.

Start from the actual request, repository/architecture, assets and existing authorization. Resolve which mode is requested: source review, authorized verification, remediation or reporting. Use available skill metadata and the supplied project; no particular agent, shell or security tool is assumed.

Build an assessment brief with actor/asset/trust-boundary/invariant, relevant environment/build and evidence availability. Route by the boundary being crossed, not just a technology keyword. Cover browser/client, API/object/property/function, identity, business state, data/parser, crypto, network/proxy, cloud/workload, supply chain, mobile/desktop/native, AI/tool and telemetry/failure domains where the actual system contains them. Mark absent domains not-applicable with evidence; unavailable access stays not-assessed.

Choose the smallest set of specialists that can answer each material hypothesis. For a JS bundle, recover call/provenance before investigating a server endpoint. For 403, establish the denial source and protected-effect oracle before any variation. For cloud and native code, resolve provider/ABI/identity details before translating generic advice. Load one relevant domain playbook and the technique guide; do not load all skills into every task.

Prioritize reachable sensitive invariants over uncorrelated scanner output. For each selected check, record its disproof/control and the smallest decisive next artifact. Keep inventory, a suspected flaw, source-supported proof and dynamic observation distinct. Reuse supplied evidence; do not repeat live checks merely to populate a checklist.

Track changed state, test budget, evidence IDs, unresolved questions and dependencies. Completion means the requested scope is covered or its gaps are explicitly explained, useful reports/remediation are delivered, and original failing plus legitimate controls are retested when claiming a fix. It never means every possible vulnerability is absent. Preserve one report per independent cause, then add supported chain context if useful. No external submission or delegation is implied; use subagents only when separately authorized.

Use [assessment-brief.md](assets/assessment-brief.md), [runtime contract](references/runtime-contract.md) and the [planning catalog](assets/control-catalog.json). [Reference](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) accessed 2026-10-27 provides analyst context, not a statement that authorization or testing occurred.
