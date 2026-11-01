# AI data, instruction, artifact and tool trust separation

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Map user instructions, external content, retrieved chunks, model artifacts, generated output, tool calls and deterministic execution services as distinct trust boundaries. Define the product task and protected data/action contract before choosing an evaluation.

Use small owned corpora, canaries and stub actions. A live model trial needs recorded model/settings/attempt budget and permitted data handling. A mocked model tests the downstream sink/gate, not the probability that a real model emits that output. A checkpoint must be inspected safely before any potentially executable load.

A surprising answer, refusal bypass or repeated prompt text is not automatically a security boundary violation. A model refusing a prohibited tool call is not proof that the tool service enforces permissions. Retrieval access is a concern even if the final answer omits already leaked context. Mark unverified chain links.

Keep authorization, resource bounds and credential trust outside model decisions. Retest valid tasks, rejected cross-tenant/resource calls, wrong token purposes and actual downstream output handling. Do not claim that prompt wording or a handful of failed attacks establishes universal resistance.

## Evidence before conclusion

- task/data/action boundary and actor/tenant
- content/artifact/token provenance and deterministic gate
- model/version/settings and actual-versus-stub path
- canary/chunk/ledger/sink result and trial budget
- legitimate-task controls and residual uncertainty

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
