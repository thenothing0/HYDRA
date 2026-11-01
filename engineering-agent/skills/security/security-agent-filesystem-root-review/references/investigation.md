# Investigation: Agent broker file-root capabilities and grant-generation revocation

## Trace in the actual implementation

Follow model-supplied paths through normalization and descriptor/open logic. Compare the final object to the user-authorized workspace rather than only a textual prefix.

## Implementation decisions

Resolve paths at the actual file operation, including parent symlinks, directory handles and races between check and use. A lexical startswith check can misclassify sibling names, while sandboxed mount isolation may deny the path independently. Use disposable local roots and marker files; privileged fixture creation of a symlink is not proof the untrusted actor can create it.

## Operational method

Specialize in broker-issued workspace/root capabilities: grant ID, canonical root, allowed operations, user/task ownership and revocation generation. Resolve the actual file descriptor/path at use and compare it with the current capability; an old tool handle must not silently retain authority after a narrowed grant if policy revokes it. Test disposable marker roots and a stale broker handle. Ordinary traversal/link mechanics without a changing agent grant belong in filesystem review.

## Discriminating verification

Grant a disposable file-root capability for markerA, then narrow/revoke it and reuse the old broker handle under the declared generation policy. Compare a fresh permitted handle and the stale context without accessing real private files.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A prompt asking for an outside path is not access; an external file read by setup code must not be attributed to the agent tool.

## Repair acceptance

Enforce final file-object authority and retest legitimate nested paths, link/rename races in local fixtures and explicit user grants.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
