# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Parent grant defeats child deny
The synthetic rules grant read at /profiles to any authenticated user and deny it at /profiles/$uid/private. User B reads A's synthetic private child. Show the shallow grant; the child deny is ineffective under RTDB inheritance.

### Validation is not delete authorization
A record's .validate demands an owner field, but .write allows any authenticated client. Deleting the record may bypass the non-null schema validation while remaining authorized by .write. Diagnose the write rule, using an emulator and a synthetic record.

### Admin setup is not a bypass
The test suite seeds data through the Admin SDK, then an unauthenticated client is denied by rules. The setup succeeds by design and cannot be reported as public write access.
