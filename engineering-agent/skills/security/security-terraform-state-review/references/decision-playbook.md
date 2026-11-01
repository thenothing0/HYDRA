# Publisher, source, build and artifact consumption trust

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Trace the trust chain from source/event identity to resolved dependency, build execution, artifact identity and privileged consumer. Separate names/versions from publisher/source binding and exact digest. Record who can edit workflows, runner state, registry settings, cache selectors and promotion rules.

Inspect source and metadata before running any tool that can fetch or execute build hooks. A package-manager dry-run, model loader or Terraform plan can still run code or contact services. Use inert offline candidates, reviewed local fixtures and fake secret markers; do not publish a package or run untrusted build code for proof.

A valid signature/attestation does not authorize its producer for this consumer. A hash next to attacker-controlled bytes is not independent provenance. UI secret redaction is not artifact omission, and deleting a value in a later layer does not erase prior layers/backups.

Bind the consumer to an approved producer/source/artifact and verify before privileged use. Retest legitimate builds/updates, wrong source/producer/digest, fallback paths and historical artifact recipients. Keep dependency advisories distinct from reachable substitution or workflow privilege-crossing findings.

## Evidence before conclusion

- producer/source and consumer authority contract
- event/checkout/resolution and artifact digest trace
- who controls selectors, hooks, runner and cache state
- inert selection/consumption proof and exact tool side effects
- allowed promotion/update and rejected-source controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
