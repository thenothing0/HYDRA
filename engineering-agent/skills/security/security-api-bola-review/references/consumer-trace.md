# Follow the object through an indirect operation

## Source path to resolve

Do not stop at the route middleware. Build this trace with actual locations:

```text
authenticated principal
  -> request.document_id
  -> document lookup (owner/tenant/share state)
  -> action policy for that document
  -> job payload / service credential
  -> worker document lookup
  -> result owner + result download
```

The job can belong to A while its contents belong to B. Job ownership and content authority answer different questions. Record the exact identifier checked at each edge; checking a path tenant while consuming a body tenant can leave the protected object unbound.

## Inspect the repair at the consumer

Illustrative pseudocode, not a framework API or a complete implementation:

```text
# vulnerable: endpoint and job ownership are allowed, document is unbound
doc = documents.by_id(request.document_id)
job = jobs.create(requester=principal.id, document_id=doc.id)

# intended authority boundary, using the product's actual policy
doc = documents.by_id(request.document_id)
require(can(principal, "export", doc))
job = jobs.create(requester=principal.id, document_id=doc.id)
```

If grants must remain valid until worker execution, the worker must evaluate the declared current policy too. If the product intentionally grants an immutable enqueue-time snapshot, validate the snapshot authority/contents instead of imposing a new lifetime contract. For nested/batch references, establish authority over every consumed object; a single authorized outer record does not authorize arbitrary children.

## A decisive comparison

Record A reading A, B reading B, A denied direct B, then A's export of B. Preserve the same A session throughout the candidate path. A 202 with no content is a candidate until worker/result evidence exists. An A-owned job returning B's private marker completes that path. A later 403 is insufficient if a prohibited result was already produced/published.

Repair acceptance includes A-to-A export, denied A-to-B export and absence of B data in the relevant output. A missing worker is a precise coverage gap. Report the source trace if complete, otherwise keep the indirect path unverified; do not compensate by enumerating unrelated IDs.
