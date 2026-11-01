# Security event, detection and abnormal-state behavior

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Define the security decision/event that should be visible and the operational response it is expected to trigger. Trace actual producer fields, redaction, transport, storage, correlation and alert routing; a logging function or enabled rule is not end-to-end delivery.

Use synthetic correlation markers and bounded fault injection in owned fixtures. For abnormal states, identify what has committed and what still needs authorization, cleanup or compensation at each failure point. For detection, observe the routed event/alert and timing rather than only local log output.

Missing convenience logs are not necessarily a security defect, and a caught exception does not establish fail-closed behavior. Review sensitive values, caller-forged log structure, partial transactions, exhausted resources and retries against the actual policy and threat model.

Fix event integrity/delivery or the fail-open/cleanup decision. Retest a representative security event, no secret leakage, intended alert destination and recovery/normal operation. Keep infrastructure outages or unseen downstream systems as explicit coverage limits.

## Evidence before conclusion

- required event/failure security contract
- producer-to-alert or pre/post-commit trace
- synthetic correlation and observed destination/timing
- redaction/integrity and compensation result
- normal operation and recovery controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
