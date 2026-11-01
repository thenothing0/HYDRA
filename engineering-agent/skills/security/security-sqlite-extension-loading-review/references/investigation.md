# Investigation: SQLite extension-loading authority in an embedded application

## Trace in the actual implementation

Determine whether lower-trust SQL or configuration can select an executable extension under the application process identity.

## Implementation decisions

Distinguish native sqlite3 extension-loading enablement from SQL load_extension availability and the wrapper connection flags. Ordinary SQL injection does not automatically imply extension execution. The host must expose loading and a reachable library source; inspect the exact connection and use an inert local stub rather than loading an untrusted native binary.

## Discriminating verification

Use a local reviewed stub or source trace proving load reachability; never load an untrusted binary merely to validate a concern.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

SQLite library presence or SQL input alone is insufficient if extension loading is disabled or inaccessible.

## Repair acceptance

Disable unneeded extension loading or constrain its trusted caller/source, preserving required embedded database operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.sqlite.org/loadext.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
