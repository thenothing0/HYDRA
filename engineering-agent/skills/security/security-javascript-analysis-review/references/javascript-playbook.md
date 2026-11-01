# JavaScript review: from artifact to supported finding

## Collect an attributable corpus

Record the allowed application/build, actual bundle URL or repository path, content hash, collection time and role/session used. Keep the original bytes; pretty printing and source maps are navigation aids, not replacements for source locations. A chunk name, stale build or development-only module must not be silently attributed to production.

Inventory entry bundles, lazy/dynamic imports, workers and framework runtime configuration that the permitted application actually references. Treat additional hosts, source-map source URLs and dependency registries as candidate scope, not automatic authorization to fetch them. Never execute a downloaded bundle, import its modules, run its build config or install its dependencies merely to inspect it.

## Recover source without granting it authority

Use supplied maps and embedded sources to understand code. Preserve the generated-file hash and source-map hash, and verify that the map applies to this build. A mapped filename is an untrusted label. Do not write files using sources/sourceRoot/file as filesystem paths or fetch indexed section URLs automatically. Missing sourcesContent means missing source; it does not mean an empty original file. Decompiled names or mapping positions may be inaccurate.

The optional source_maps.py tool supports bounded local v3 embedded-content inventory and opaque extraction. It does not validate mappings/VLQ positions or prove original-source fidelity. Output may contain sensitive original code: keep it within the authorized workspace and review it before sharing.

## Separate inventory from data flow

Parse with the grammar appropriate to the input: classic/module JavaScript, JSX or TypeScript. The optional pinned Acorn helper parses JavaScript modules/scripts and inventories literal call arguments with original locations. It does not resolve lexical bindings, aliases, wrappers, dynamic expressions or interprocedural flow. A parser failure is a coverage gap; no inventory is emitted as if the file were clean. Do not use a regex match as proof that a call is executable JavaScript.

For each material candidate, derive the chain manually or with appropriate analysis tooling:

| Trace | Required question |
|---|---|
| Entry and actor | Who controls this input, route, stored object, message or configuration? |
| Request | Actual receiver/library, method, base origin, URL construction, credentials, tenant and call reachability? |
| Transform | Which decoding, sanitization, coercion or validation applies before use? |
| Consumer | Browser HTML/script/URL, Node process/filesystem, API operation, storage or native bridge? |
| Authority | Which server/privileged gate enforces the intended actor/object/action/field rule? |
| Decisive evidence | What harmless effect or complete source proof distinguishes a defect from an intended feature? |

Follow auth/session state, interceptors, error/fallback paths, role-dependent renderers, exports, workers and lazy paths only when they participate in the hypothesis. Link an endpoint candidate to an authorized API/access-control assessment; do not claim the server is vulnerable because client code can address it.

## Decision examples

* A literal /admin/export found in an unused module: inventory lead. Establish shipping/reachability and actual role policy before testing it.
* A client role flag reveals a button while the server still denies the operation: no demonstrated server authorization bypass.
* A public SDK project key or publishable payment identifier: determine its intended authority; do not label it a private credential or test it against a service.
* A lower-trust stored field reaches another owned test identity's dangerous browser sink: preserve the input-to-consumer trace and inert effect, then report the actual sink/root cause.
* A published source map: useful provenance. Disclosure impact requires genuinely protected content and an unauthorized access path; availability alone does not establish severity.

## Optional tools and limits

Run `node scripts/analyze.mjs INPUT.js --output NEW.json` for AST inventory. Node is optional; there is no npm install. scripts/vendor includes Acorn 8.19.0, its MIT license and verified upstream tarball provenance. Input is never imported/evaluated and map URLs are not fetched. Output refuses overwrite, caps input at 2 MiB and marks unresolved calls; it can miss aliases and wrapper APIs.

Run `python scripts/source_maps.py INPUT.map --output NEW_DIRECTORY` for embedded-source extraction. Python 3.10+ standard library only; map size/depth/count/content budgets are enforced before output. Both tools are analyst aids, not scanners that confirm vulnerabilities. Use external process time/memory limits for large hostile corpora; parser CPU behavior is not universally bounded by a file-size cap.

## Deliverable

Produce a corpus/provenance inventory, candidate ledger with unresolved expressions, selected source-to-consumer traces, supported individual findings, and explicit gaps. Preserve the exact original location and transformed/mapped source separately. Verify the actual remediation on the affected feature and legitimate inputs; hiding code or removing a comment is not a substitute for repairing an authority/sink boundary.

## Additional interpretation boundary

The AST helper reads supplied files as UTF-8 text and reports JavaScript line/column locations, not original wire-byte offsets. It does not emulate browser charset/content-type handling; establish that source representation before attributing a browser behavior.
