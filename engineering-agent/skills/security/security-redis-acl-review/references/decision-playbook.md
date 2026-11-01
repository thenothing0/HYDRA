# Database, broker and persistent data authority

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Record the actual application principal and role/group/context selection, not just an administrator session. Define allowed query/command/topic/group/key/row/transaction tuples and who may change the enforcement policy. Authentication and transport access are not object/data authorization.

Use two synthetic tenants and the actual runtime role or a clearly labeled evaluator. Observe returned data and persisted writes, and compare the entitled operation. Trace connection-pool context reset, background consumers, retries and stale caches when they affect authority.

An owner/superuser may intentionally bypass a row policy. Key prefixes, logical database numbers, predictable job IDs and visible topic names do not themselves establish isolation or its failure. Evaluate complete policies, resource patterns, selectors and active configuration for the product version.

Repair effective data authority and trusted context lifecycle. Retest allowed and denied reads/writes, multikey/batch/transaction paths and reuse/reload behavior. Do not dump live databases, secrets or consumer records to establish a concern.

## Evidence before conclusion

- real runtime principal and tenant/context source
- product/version and effective policy/selector tuple
- synthetic ownership, command/query and persisted outcome
- connection/pool/worker or reload timing
- legitimate operation and denied cross-authority controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
