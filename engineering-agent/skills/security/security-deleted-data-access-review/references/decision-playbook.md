# Data access contract and lifecycle propagation

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Define the concrete privacy/access promise and the actor who should lose access at each lifecycle state. Distinguish display hiding, soft deletion, scheduled purge, legitimate retention and prohibited disclosure; legal retention duties are outside this technical workflow.

Use synthetic canaries and a retained control across the evidenced API/cache/search/export/backup or restore path. Check at the promised completion point and identify the actual recipient/authority. A copy in owner-restricted retention is different from a copy still reachable by a prohibited actor.

Do not infer that every stored byte must disappear immediately or that a UI label establishes purge. A signed capability can retain a separately documented lifetime; compare actual issuance/access policy. Unsupported physical/media erasure remains untested, not silently certified.

Repair the promised access transition and prevent accidental re-publication during restore or delayed processing. Retest legitimate retained/recovery data, denied deleted-record delivery and time/state propagation with declared limitations.

## Evidence before conclusion

- specific product access/deletion promise and timing
- synthetic record/canary and actor/recipient
- every tested retained/delivery/restore path
- actual residual exposure versus authorized retention
- valid recovery/retained-data and denied-access controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
