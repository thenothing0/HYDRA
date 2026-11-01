# Investigation: Ruby YAML loader mode, permitted classes and object construction trust

## Trace in the actual implementation

Follow lower-trust YAML through the actual loader configuration and determine whether arbitrary constructors or authority-bearing object state are accepted.

## Implementation decisions

Resolve Psych/Ruby version, safe_load/unsafe_load/load behavior, permitted classes and aliases at the actual callsite. Do not assume every YAML loader constructs arbitrary objects or every permitted class is dangerous. Use a harmless custom fixture class only in an isolated harness, trace reachable callbacks, and avoid executing untrusted deserialization gadgets.

## Operational method

Retain loaded Psych gem version, actual method owner/implementation and safe_load/load/unsafe_load arguments, including permitted classes/aliases. Ruby version alone can be insufficient when the gem or wrapper differs. Trace the permitted class construction/callback and downstream use in source before selecting a harmless isolated fixture class. A generic YAML parse success or an old reference version does not demonstrate object execution in the installed loader.

## Discriminating verification

Use an isolated fixture with primitive data and an inert custom class; compare allowed plain data and rejected unexpected object construction.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

YAML parsing itself is not unsafe object loading; a safe loader rejecting the test type disproves that specific path.

## Repair acceptance

Use context-appropriate safe loading and explicit data validation, retesting valid aliases/types required by the feature.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://ruby-doc.org/stdlib-3.1.1/libdoc/psych/rdoc/Psych.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
