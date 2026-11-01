# Evidence and assessment tools

`scripts/security_workflow.py` uses Python 3.10+ and the standard library. It is an evidence helper, not a vulnerability scanner. Inspect/adapt the supplied templates in a task working directory; never store real credentials in a skill folder or deliver them in the package.

## Request metadata collection

Copy [http-plan.example.json](../assets/http-plan.example.json) to the working directory and replace the example with already authorized endpoints. Only exact HTTP(S) origins and explicitly listed GET/HEAD requests are supported. The tool validates the whole plan before sending the first request. Default budget is five requests, hard cap twenty, interval at least 0.2 seconds. It does not follow redirects or automatically retry. A 429, 503 or transport failure stops the run.

Optional `headers_file` names a JSON file of profiles beside the plan, for example `{"owner":{"Authorization":"Bearer <working credential>"}}`. Requests select a profile with `"profile":"owner"`. Credential profiles require HTTPS and support only Authorization, Cookie, Accept, User-Agent and Origin. Keep that file private; do not attach it to a finding. Ambient system proxies are disabled and TLS verification remains enabled.

Run:

```text
python "<skill-root>/scripts/security_workflow.py" collect "<work-root>/http-plan.json" --output "<work-root>/http-evidence.json"
```

The output keeps opaque request IDs, exact origin, path hash, query field count, status, header names and at most a 64 KiB body-sample hash/size. It stores no request credential values, URL query values, response header values, redirect destinations or raw body. The socket inactivity timeout is 10 seconds; this is not a global engagement deadline. Inspect body/field/state evidence separately through approved tools if needed, redact it, and keep its provenance. Metadata equality/differences and a 200/403 response do not prove a vulnerability or denial of side effects.

## Assessment consistency and rendering

Copy [assessment-template.json](../assets/assessment-template.json); fill target/scope, coverage and evidence from actual work. Evidence paths must stay inside the assessment file's folder; reference only reviewed/redacted files and their actual SHA-256. Evidence collection times need ISO 8601 UTC offsets. Use simple opaque IDs, not tokens or personal data.

```text
python "<skill-root>/scripts/security_workflow.py" check "<work-root>/assessment.json"
python "<skill-root>/scripts/security_workflow.py" render "<work-root>/assessment.json" --output "<work-root>/report.md"
```

The checker rejects missing/changed evidence, invalid IDs/references, undocumented coverage gaps, category mismatches, unsupported confirmation fields, and fixed claims without passing negative/positive/side-effect retests on the named fixed build. Retests need execution evidence and expected/observed outcomes. A code trace can support confirmation but cannot by itself close a tested fix. Output creation refuses to overwrite an existing file.

The checker validates declared structure, hashes and consistency. It cannot prove that a claim is true, an authorization statement is valid, evidence is genuine or a patch works. A human/agent reviewer must evaluate the underlying artifacts and security reasoning. Rendered output is a starting report; retain any additional application-specific evidence needed by the receiving program.

Read [assessment-format.md](assessment-format.md) for the exact field contract and closure rules. Pseudonymous path hashes and body hashes are not anonymization and may remain linkable or guessable; protect evidence according to its sensitivity.
