# Native lifetime, arithmetic, OS object and privilege boundaries

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Establish ABI/types, object ownership, process token/UID/GID, file/parent/service permissions and the actual input-to-consumer path. Derive the specific invariant mathematically or from effective OS authority before selecting a test.

Use source proof, read-only effective-access inspection or tiny owned inert harnesses. A sanitizer proves only the instrumented behavior it catches; unsupported toolchains mean no sanitizer run was performed. Avoid oversized allocations and stop at the first invalid memory operation, not an exploitation objective.

Unsigned wrap may be intentional; a generic UB sanitizer excludes some suspicious conversions and unsigned arithmetic. An unquoted service path needs a controllable candidate path and privileged trigger. A no-follow flag on a basename does not secure every parent component. Readable configuration is not writable authority.

Fix bounds/lifetime/representation or the actual privileged object/descriptor gate. Retest valid boundary values, error cleanup, effective low-privilege access and legitimate maintenance. State untested platform/race/ABI variants and never infer RCE or administrator takeover from a crash or string pattern alone.

## Evidence before conclusion

- ABI/types or effective OS token/identity
- precise lifetime/range/object-permission invariant
- allocation/free/use or check/open/consume trace
- tiny harness/read-only evidence and compiler/platform limits
- valid boundary/error/maintenance controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
