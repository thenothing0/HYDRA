# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Hidden field still serialized
A server component passes an entire owned user record to a client avatar component. The avatar renders only displayName, but the received payload includes a protected synthetic recovery value. UI invisibility does not prevent disclosure; demonstrate the emitted value and the observer's lack of entitlement.

### Server-only computation
A server component uses a secret to compute a public boolean and passes only that boolean. The secret does not appear in delivered props or response bytes. Its server-side use is not a source disclosure.

### Different root cause
A correctly projected DTO belongs to the wrong owned tenant because a shared cache omitted identity context. Report cross-tenant cache/authorization reuse, rather than calling every serialized field excessive exposure.
