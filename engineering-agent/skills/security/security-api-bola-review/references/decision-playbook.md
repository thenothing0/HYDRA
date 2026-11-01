# Actor, resource, operation and field authority

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Construct the entitlement tuple (actor/tenant, resource owner/state, operation, readable/writable fields). Derive it from a real product rule, not a route name. Compare a denied actor, a candidate crossing and an entitled actor on the same build/resource policy. The endpoint being available does not authorize every object or property.

Trace the representation checked and the representation used: normalization, nested identifiers, batch elements, export workers, method dispatch, proxy identity and service credentials. Determine where authority is enforced before any side effect. A downstream privileged identity can legitimately act for the caller only within the documented delegation.

Reject status-only claims: a soft denial may be 200; a 403 may follow an already committed operation. Public/owner/admin intended data, ignored forbidden properties and a different handler do not prove bypass. Separate object, function, property and session failures so the report names the actual missing decision. A complete source proof can suffice, but identify the concrete policy/reachability and unexecuted effect.

Repair at the authoritative consumer using normalized trusted identity and explicit policy. Retest the original failing tuple, the permitted tuple and unchanged denied state across the originally affected entry points.

## Evidence before conclusion

- actual entitlement rule and source
- actor/session/tenant and resource owner/state
- entry-to-authoritative-consumer trace
- protected bytes or commitment, plus rejection timing
- denied and entitled controls on identified build

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
