# Evidence and verification

Choose applicable controls in [advanced-checks.md](advanced-checks.md). Record actual coverage and evidence; the catalog is not an exhaustive security certification.

## Source-only mode

A complete reachable code/configuration trace can support a confirmed finding without executing a dangerous effect. State that dynamic reproduction was not performed. If reachability or intended policy is unknown, mark the item suspected or unverified and name the missing evidence. Never mark a category secure because no grep pattern matched.

## Tools and evidence selection

Use rg and the project’s route/schema/config inventories to locate candidate entry points; validate candidates through callers and effective settings. Prefer existing project tests and isolated fixtures over adding an unreviewed scanner. Record tool version, exact command, scope, exit status and relevant output when tools run. Scanner output is a lead until its affected path, prerequisites and security effect are checked.

## Local laboratory

Run `python scripts/verify_lab.py` from this skill folder for its self-contained, standard-library-only training fixture. It uses synthetic in-memory data and no network services. Read the source before adapting it. Its passing result demonstrates the encoded security invariants and deliberately insecure contrasts only; it is not a scan of the target and does not evaluate model detection accuracy. Apply the matrix to the real stack separately.

## Actual lab coverage

Covered: Recipient/account binding and one-time reset using an in-memory delivery sink.

Not covered: No actual email, expiry, session revocation, MFA, federation, token issuer/audience, or throttle behavior was tested. The fixture is not a production recovery implementation.

See [example-report.md](example-report.md) for an evidence-based worked finding and the distinction between an implementation comparison and an actual patch.
