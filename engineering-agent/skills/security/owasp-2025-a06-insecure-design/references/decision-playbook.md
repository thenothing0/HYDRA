# Design requirement, abuse case and control placement

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Describe assets, actors, trust boundaries and product security invariants before applying a taxonomy. Trace ordinary and abusive state/data flows and identify which server/service owns each decision. Separate missing design controls from incorrectly implemented existing controls.

Select concrete reachable abuse cases using actual interfaces, identities and resource budgets. Ask what evidence would disprove each concern and route to a specialist when a protocol/provider/interpreter detail decides it. Architecture diagrams alone do not prove an implemented failure.

Do not label every absent best practice a vulnerability. Establish the intended product requirement, plausible lower-trust capability and actual protected consequence or complete source proof. Broad OWASP categories are assessment lenses, not exhaustive certifications.

Choose control placement that survives alternate entry points, failures, retries and state transitions. Verify the original invariant, normal product flows and relevant changed side effects. Preserve unexamined domains and design assumptions in the completion ledger.

## Evidence before conclusion

- assets/actors/boundaries and product invariant
- actual normal/abusive flow and decision owner
- concrete reachable hypothesis and disproof
- source/runtime control evidence with assumptions
- legitimate workflows and residual design risks

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
