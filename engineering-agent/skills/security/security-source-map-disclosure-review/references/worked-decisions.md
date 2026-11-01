# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Public frontend code
A production map embeds a public React component, endpoint names and library comments. The same runtime calls exist in the bundle. Record source exposure and any publication-policy issue. Do not claim database access or a leaked backend credential.

### Separate protected material
A map embeds a non-executed server module with a private signing key. Attribute the exact map and module, redact the value, and establish its credential purpose from owned configuration. Report the disclosure even if current validity is unknown; do not authenticate with it to make the report appear stronger.

### Broken provenance
A map has `file: app.js`, but the saved app.js belongs to another build and the suspected consumer cannot be found there. The missing build correlation remains a gap. Matching filenames do not close it.
