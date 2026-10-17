# Applying AI Engineering Operating System V5 to HYDRA

The user supplied AI-EOS V5 as both an engineering work method and a phased
product direction. HYDRA retains its identity and existing command surface.
This document records implemented behavior and bounded next steps; the complete
309-section specification is not claimed implemented.

## Phase 1: durable state, run limits and handoff

| Requirement references | Implemented behavior | Evidence |
| --- | --- | --- |
| 15–18, 21, 43 | Existing session schema 1 is validated on load/save, including types, status, workspace, timestamps, revisions, stored originals and run counters; checksums and stale-generation refusal remain enforced | `tests/test_engineering_governance.py`, session tests |
| 49, 65–66, 72, 220 | Per-run request, tool, elapsed-time, context-character, observed-token and failure limits; repeat failures stop; independent monotonic deadline; stop reason and run ID persisted | Governor and agent tests |
| 12–14, 205, 283 | Existing cancellation, denied approvals and process cleanup preserved | Terminal/process tests |
| 109, 214–216, 235–237, 242–246 | Run-correlated events and a validated handoff export with source checksum, evidence references and explicit limitations | Handoff CLI and terminal tests |
| 299–302 | No model-quality, financial-cap, persistent-learning or complete-platform claim based only on fixture tests | Status and provider documentation |

Use the limits with either CLI tasks or the interactive terminal:

```sh
python -m hydra tui --workspace /path/to/project --max-tool-calls 20 --max-failures 4
python -m hydra run "Inspect this project" --workspace /path/to/project --max-tokens 12000 --max-context-chars 64000
python -m hydra handoff SESSION_ID --workspace /path/to/project > handoff.json
```

Inside the terminal, `/status` shows the selected session's counters and stop
reason; `/handoff` displays its committed export. A handoff does not mutate state,
copy raw command output, assert that every plan item is finished, or change
permissions. Resume requires a fresh operator invocation and records a new run
with new limits; previous run records remain in session events.

### Exact limit semantics

- Defaults remain 30 model steps and 600 seconds. Tool calls default to the step
  limit. `--max-failures` counts failures over the whole run, not just consecutive
  failures; three repeated identical failing actions also stop the run.
- Context limits measure serialized prompt **characters**, not tokenizer tokens.
- `--max-tokens` uses provider-reported cumulative input/output counts relative to
  the start of that run. A completed request may cross the ceiling. Its action is
  then refused and no next request is sent. This is not a provider-side quota or
  a hard financial cap. Missing, invalid or decreasing counts block a token-limited
  run rather than fabricating zero usage. The first request can be needed to learn
  that a provider does not report usage.
- Provider billing, external tool spending and OS-level resource isolation are
  not controlled by this phase. Approved commands still use normal OS permissions.
- Schema 1 is retained; valid old sessions load without a rewrite. Unsupported or
  corrupt state fails explicitly. Future incompatible formats require a separately
  tested migration instead of silently relabelling old snapshots as V5 state.
- Checksums detect accidental corruption and stale export state. They do not
  authenticate a snapshot against an attacker controlling the same user account.

## Next phases

1. **Capability contracts and policies** (5–11, 124–128, 189, 195–198): versioned
   capability metadata, typed permissions, scoped/expiring grants and explainable
   denials; preserve the existing process, browser and Burp boundaries.
2. **Project memory and acceptance evidence** (27–43, 55–64, 95–97, 143–145,
   227–244): project-scoped facts with provenance/freshness, explicit acceptance
   criteria and traceable checkpoints. No cross-project retrieval by default.
3. **Evaluation and release evidence** (99–121, 159–164, 260–268): a versioned
   golden/adversarial task dataset, comparable baselines, recovery tests and
   meaningful task-success metrics. Fixture success alone is not model benchmarking.
4. **Optional advanced orchestration** (44–54, 74–83, 138–142, 206–225): independent
   worker contracts, budget reservations, richer tracing, pricing, scheduling and
   controlled fallback only when a verified use case justifies the complexity.

Multi-tenant hosting, encryption/key management, compliance certification,
production deployment, self-modification and automatic learning are separate
projects with their own acceptance criteria. The supplied specification's
conditional clauses do not make these services available automatically.

## Development method

For each phase: identify concrete requirements, inspect current state, make the
smallest useful change, run appropriate regression checks, record what was
verified and what remains unknown, and publish the reviewed implementation.
Human interruption and existing authorization remain effective throughout.
See `EOS_V5_STATUS.json` for the machine-readable phase record and source digest.
